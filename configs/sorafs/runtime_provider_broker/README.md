# Runtime-provider broker deployment contract

These assets supervise an operator-supplied V1 runtime-provider broker. The
repository supplies the authenticated client/server protocol and the
credential-free process shell; it does not supply a concrete signing backend,
credential store, WebAuthn service, immutable query, sealed store, archive, or
network backend registry.
The installed executable must statically link a reviewed deployment-owned
implementation of RuntimeProviderBrokerBackendRegistryV1.

The service CLI requires two public inputs:

    --catalog ABSOLUTE_PATH --broker-policy ABSOLUTE_TOML_PATH

That canonical catalog includes a mandatory genesis-derived `NetworkId` in
addition to the display chain label. Catalogs exported with the retired
optional-network schema are rejected; regenerate the artifact for the exact
deployment and roll broker and clients together.

Do not add credential, private-key, token, plugin, or test-provider arguments.
The public policy file contains the fields of `[runtime_provider_broker]`
directly, without a section header. Install `policy.linux.toml` or
`policy.macos.toml` as the fixed `policy.toml` below. Its endpoint must match
every stock client. `observer_operation_timeout_ms` defaults to 15000 and
accepts only 1 through 15000; ambient environment values cannot override it.
This allowance starts at authenticated observer-operation admission before
provider dispatch and spans completed-reply encoding and publication. Local
continuation retains that same absolute deadline. Socket ingress and handshake
retain their separate transport bounds. A synchronous provider already running
cannot be forcibly cancelled; a late returned reply cannot be published.
Provider objects retain private material internally.

## Fixed paths and identity

| Property | Linux | macOS |
| --- | --- | --- |
| Service identity | iroha:iroha | iroha:iroha |
| Executable | /usr/local/libexec/iroha-runtime-provider-broker-v1 | /usr/local/libexec/iroha-runtime-provider-broker-v1 |
| Public catalog | /etc/iroha/runtime-provider-broker/catalog.norito | /private/etc/iroha/runtime-provider-broker/catalog.norito |
| Public broker policy | /etc/iroha/runtime-provider-broker/policy.toml | /private/etc/iroha/runtime-provider-broker/policy.toml |
| Threshold credential handoff | systemd `CREDENTIALS_DIRECTORY` | launchd-opened `/private/var/run/iroha-runtime-provider-broker-credentials-v1/threshold.bundle` FIFO |
| Runtime directory | /run/iroha-runtime-provider-broker-v1, mode 0700 | /private/var/iroha/run, mode 0700 |
| Broker socket | /run/iroha-runtime-provider-broker-v1/runtime-provider-broker-v1.sock | /private/var/iroha/run/runtime-provider-broker-v1.sock |

The broker and every stock client must run with the same effective UID.
Supplementary-group access is not a substitute for the peer-credential check.
The packaged broker creates the configured socket with mode 0660. The macOS catalog path
names /private/etc explicitly because /etc is a symlink and the process shell
rejects symlink path components.

Peer authorization is evaluated independently for every accepted connection.
An unauthorized UID is dropped without processing a request, while the broker
continues accepting later authorized clients. Failure to read peer credentials
is a transport failure and stops the serving loop because the broker cannot
establish the authorization boundary.

The broker holds a single-link, mode-0600 instance lock in its runtime
directory for its full serving lifetime. After an unclean exit releases that
lock, the next process removes only an exact inactive socket with the expected
owner, mode, and stable device/inode identity before rebinding. Every other
pre-existing entry fails startup without being removed.

## Consensus threshold-signer credentials

The standalone software-signer broker requires `credential_max_memory_bytes`
to match the positive bound exported in its canonical catalog. A mismatch fails
startup before credential input or backend assembly. Credential imports and
serving retain the same initially loaded catalog; executable assembly does not
reopen it. Accepted startup creates one original pool from the parsed policy and
passes it through both platform threshold handoffs; currently admitted transcript
owners retain its charges.
TODO: fund supervisor input buffers, outer `std::Arc` controls and Core custody-map
nodes with exact original owners before full memory qualification can pass.
These remaining allocations are not covered by the original-pool reservation.
A zero catalog bound is valid only for an inventory without the threshold
slot, and grants no threshold custody. This is a local operational admission
policy; it does not change transaction validity or gas accounting.

The global-beacon credential binds its public
`policy_digest` to the complete provisioned signer inventory. The digest uses
one consensus-threshold inventory domain and covers the exact role slot,
network, every public threshold session transcript, and every seat index in
canonical sorted order. Version 1 is
`SHA-256(domain || u64_be(norito_len) || norito_inventory)`;
the inventory fields are `version`, `slot`, `network_id`, and the sorted public
session-and-seat entries. Producers reject a supplied digest that does not
match that inventory. Consumers require the credential vector itself to be
strictly sorted before recomputing the digest, so only one canonical credential
ordering is accepted. Reordering provisioning input preserves the encoded
credential, while reordered wire entries, transcript substitution, or seat
substitution fail closed. Secret share components are not included in the
public inventory encoding. The header-framed top-level inventory schema name
is
`iroha.runtime_provider_broker.v1.consensus_threshold.global_beacon_public_inventory`;
credential and nested wire types also carry explicit V1 schema names so Rust
type renames cannot silently change the operator contract.

A previously resolved threshold-signer proxy reconnects and retries the whole
operation exactly once when the broker transport or live threshold-backend
qualification reports unavailability, so a supervised broker restart or
transient signer outage does not permanently strand the validator. Rejected or
drifted qualification remains a permanent stale-provider failure. The proxy
never replays protocol errors, binding mismatches, stale observations, provider
rejections, conflicts, or ambiguous outcomes.

Broker session workers use a fixed 4 MiB stack. This is large enough for the
proof-carrying threshold transcript validators in unoptimized builds while
remaining bounded by the fixed maximum number of authenticated sessions.

On Linux, a reviewed provider drop-in supplies the fixed credential name
through systemd's per-unit credential mount:
`iroha-global-beacon-partial-signer-v1.norito`. A requested file must
not be exposed through `Environment=` or `EnvironmentFile=`.

On macOS, an independent administrator creates the named pipe
`/private/var/run/iroha-runtime-provider-broker-credentials-v1/threshold.bundle`
beneath a root-owned mode-0700 directory and keeps the FIFO root-owned mode
0600 with one link. Before every bootstrap or supervised restart, the
administrator starts one blocking credential writer and, while that writer is
waiting for a reader, bootstraps or kickstarts the launchd job. launchd opens
the FIFO as standard input before changing to the shared broker UID; the writer
then emits exactly one credential bundle and closes. Do not try to finish a
write before launchd opens the read end: a FIFO has no persistent preloaded
payload, and that sequential choreography cannot complete safely. The broker
validates the already-open descriptor as a root-owned, single-link, exact-mode
0600 FIFO before reading, never resolves a secret pathname accessible to the
validator, and leaves no persistent credential bytes after the writer closes.

The V1 bundle is `IRTHB001 || u16_be(1) || u16_be(flags) ||
u64_be(beacon_len) || beacon`. Flag bit 0 denotes the global-beacon
credential; no other bit is admitted. Presence must exactly match the public
catalog slot, the credential is bounded to 16 MiB, and trailing, truncated,
empty-present, or unrequested payloads fail before socket publication. Deployment provisioning
should call the zeroizing
`encode_consensus_threshold_credential_bundle_v1` API and write its result
directly to the FIFO; do not stage the bundle, credential frames, or scalar
shares in the plist, argv, environment, public catalog, repo, or a path readable
by the shared validator UID. Even a catalog without the threshold slot receives
and validates the exact header-only bundle on each launch, keeping one immutable
launchd service contract.

Install the executable, catalog, public policy, supervisor asset, and Linux consumer drop-ins
as single-link, non-symlink regular files owned by root. They must have no
owner/group/other write bit and no set-user-ID, set-group-ID, or sticky bit. A
typical installation uses mode 0555 for the executable, root:iroha mode 0440
for the catalog and policy, and mode 0444 for the supervisor assets. Their parent
directories must be root-owned and not group/world writable. The installation
gate additionally binds the executable to the SHA-256 obtained from the
externally verified signed release provenance; a correctly named arbitrary
program is never accepted.

## Linux systemd

Install systemd/iroha-runtime-provider-broker-v1.service as:

    /etc/systemd/system/iroha-runtime-provider-broker-v1.service

The unit creates its dedicated `/run/iroha-runtime-provider-broker-v1`
directory with the service UID and mode 0700, passes the packaged public
catalog and policy paths, and gives the process no environment-based provider selector.
The broker is the sole unit that manages this directory; the validator's
separate `/run/iroha` directory has an independent lifetime. The broker
directory is recreated across broker restarts. The unit uses `Type=notify`:
the deployment-owned binary must call
`RuntimeProviderBrokerExecutableV1::serve_until_shutdown_signal_with_systemd_notify`.
That entry resolves systemd's `NOTIFY_SOCKET` before provider qualification and
sends `READY=1` only after exact backend qualification and endpoint
publication. A missing, malformed, unreachable, or disappearing notification
socket fails closed and tears down the broker endpoint before accepting a
client. This makes the consumer `After` ordering a readiness boundary instead
of merely a process-spawn boundary. Provider packages that need a specific
device, read-only vendor library, or durable sealed-store path must add a
reviewed systemd drop-in; do not weaken the base unit or place credentials in
Environment or EnvironmentFile entries. The base unit also sets `LimitCORE=0`
so provider process memory is not written to a core image.

The checked-in Linux Governance DAG consumer dependency is mandatory in an
enabled production package. Install the sorafs-governance-dag@.service.d
drop-in beside each deployment-owned Governance DAG instance unit. The
repository no longer ships a validator service or validator-specific drop-in.

The repository does not currently ship a base Governance DAG systemd unit
because its instance config path, public chain identity, and exact `NetworkId`
are deployment-specific. The drop-in uses Requires and After, so an enabled
consumer cannot start successfully without the ready broker unit. It also
pin User and Group to iroha so the stock Unix peer-credential check sees the
same effective identity, and mount the broker runtime directory read-only in
the consumer namespace so the client cannot mutate socket pathnames. Packages
with runtime providers explicitly disabled omit the drop-in and the fixed
catalog. The container validator unit is intentionally not covered: sharing
this host socket into a container requires a separately reviewed UID and mount
contract.

## macOS launchd

Install launchd/org.hyperledger.iroha.runtime-provider-broker-v1.plist as:

    /Library/LaunchDaemons/org.hyperledger.iroha.runtime-provider-broker-v1.plist

Before bootstrapping the LaunchDaemon, create the persistent
`/private/var/iroha/run` directory as iroha:iroha with mode 0700 and install the
executable and public catalog at the fixed paths above. Create and feed the
root-protected credential FIFO as described above: start the blocking writer,
bootstrap or kickstart launchd while it waits, then require both writer
completion and broker readiness before starting consumers. The plist uses no
environment variables, disables core images with zero soft and hard `Core`
limits, and restarts only after unsuccessful exit.

No validator or Governance DAG LaunchDaemon is checked in, so there is no safe
consumer plist to mutate here. Deployment packaging must bootstrap the broker
job before its consumer jobs. The consumers still fail closed if the broker
has not qualified its complete catalog and published the configured socket.

## Static installation gate

Use the read-only checker with the same exported catalog used to build the
package:

    python3 scripts/check_runtime_provider_broker_install.py \
      --platform linux \
      --install-root / \
      --expected-catalog /secure/staging/runtime-provider-catalog.norito \
      --expected-executable-sha256 "$VERIFIED_BROKER_SHA256" \
      --check-runtime-directory

For a package intentionally containing no runtime-provider bindings:

    python3 scripts/check_runtime_provider_broker_install.py \
      --platform linux \
      --runtime-providers-disabled

For a non-empty expected catalog the checker rejects a missing, linked,
non-executable, mutable, specially permissioned, inaccessible, wrongly owned,
oversized, concurrently changed, or release-digest-mismatched broker binary; a
missing, linked, mutable, specially permissioned, inaccessible, or
byte-different installed catalog; a missing, linked, mutable, specially
permissioned, tampered, or byte-different systemd/launchd asset; a missing or
non-exact Linux consumer drop-in; and, when requested, a runtime directory
whose owner or mode is not exact. The expected executable digest must come
from the externally authenticated release provenance, not from the installed
file. The macOS runtime directory is mandatory even without
`--check-runtime-directory` because launchd does not create it. Expected
supervisor and drop-in bytes are derived from the checked-in platform
templates and cannot be overridden on the command line. The broker process
remains responsible for canonical Norito decoding, backend-set resolution,
live provider qualification, and creation of the authenticated socket.

Windows has no V1 authenticated runtime-provider transport. A Windows package
must not present these templates as a functioning production broker.
