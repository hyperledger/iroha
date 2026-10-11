# Taira

Taira is SORA's persistent public testnet. The public Torii MCP endpoint is
`https://taira.sora.org/v1/mcp`; public validators and observers join that
shared network rather than creating a replacement cohort. The public-node join
contract must consume one published, signed Taira bootstrap bundle (network
identity, genesis anchor, seed peers, permissionless observer policy, on-chain
validator activation policy, and upgrade policy) plus locally generated node
keys. Runtime credentials and signing inputs stay outside the repository.
Until that bundle and the single supported node-init command are shipped, do
not present the local harness below as a public-network join procedure.

The repository's disposable four-validator harness is a local qualification
network. It is not the public Taira network and is not part of ordinary public
node onboarding. Its path is one command with an explicit prepared Inrou guest
workspace:

```bash
python3 scripts/taira_devnet.py up \
  --inrou-canary-dir /private/runtime/taira-inrou-canary
```

It builds the current `kagami`, `iroha3d_taira`, `iroha`, and `sorafs-node`
binaries, replaces
the previous script-owned bundle under `/var/lib/iroha-taira-devnet/` by
default, generates exactly four fresh-key NPoS validators for the canonical
Taira chain, with Kagami directly owning the exact storage and closed egress
profile. It validates every base configuration, then the compiled
`iroha taira inrou-stage` command stages the trusted guest and, through the
required `--bind-validator-config-dir`, atomically binds each peer to the
complete first-release Inrou backend: one
PortableVM with exact CPU, memory, writable-storage, and egress budgets plus a
separate 1600 MiB immutable guest-image materialization bound. It
starts the peers and waits for all four nodes to become ready, which also proves
that each daemon passed the artifact-free Inrou startup-boundary probe. That
probe exercises the production machine type and host CPU under KVM, private
namespaces, configured cgroup limits, anonymous QMP, QEMU user networking, the
private loopback connector, and the owner firewall. The command then stages and
preseeds the required guest, boots four isolated workload replicas, and proves
their authoritative public route. It also
submits one signed `iroha tx ping`, waits for its typed `Applied` status,
requires all four committed heights to advance and converge, and checks that
every generated MCP endpoint can initialize and list tools. The fixed
`local-release` build explicitly targets the native Rust host triple, clears
ambient target-dir, target, compiler/wrapper, incremental, and build-identity
environment overrides, and selects only
`<target-dir>/<triple>/local-release` outputs from a direct owner-controlled
tree disjoint from the disposable network. It never accepts prebuilt binaries.
It records the exact `optimizations` HEAD plus a collision-safe pre/post
observation of the tracked diff and non-ignored untracked files. That observation
is a race detector, not proof of which source Cargo consumed. It requires all
four live validator build identities to match the observed HEAD and target, the
CLI to report the same HEAD, hashes every selected executable before the cohort
is replaced and after qualification, and fails if the observation or binary
evidence changes.

The JSON names this record `source_observation`, scopes it to the Git HEAD,
tracked diff, and non-ignored untracked entries, and sets
`cargo_source_consumption` to `not_proven`. Ignored files, Cargo configuration,
build-script inputs outside the worktree, the toolchain, and dependency caches
are outside that observation. Exact source provenance belongs to the separate
signed immutable release corridor.

`up` is an Inrou startup-boundary and guest-workload qualification command. It
fails before building
or replacing a cohort unless the host is Linux AArch64, the command starts as
uid 0, and `/dev/kvm` exposes KVM API version 12. The daemon then remains the
authority for the root-custodied runtime closure, locked service identities,
private namespaces, cgroup-v2 limits, anonymous QMP, and firewall posture.
Provision the four canonical same-host identity slots before running it:

- `iroha-inrou-0`, uid/gid `70000`
- `iroha-inrou-1`, uid/gid `70001`
- `iroha-inrou-2`, uid/gid `70002`
- `iroha-inrou-3`, uid/gid `70003`

The first-release Taira profile is shared by Kagami, Inrou staging and the
runtime launcher. Each validator permits one Inrou replica with 750 millicores
and 512 MiB guest RAM, plus mandatory 250-millicore/256-MiB VMM overhead.
Hydration and prepared-runtime caches each have capacity one. The canonical
canary has a 1536 MiB root volume, 16 MiB temporary filesystem and 64 MiB app-data
volume; its durable state is bounded to 1024 bytes. The verified Debian asset
helper must normalize the freshly extracted ext4 filesystem to exactly 1536 MiB.
It uses official e2fsprogs on a private unmounted copy, checks the filesystem before
and after resizing, and verifies its actual block count before truncating the file.
No forced resize or unnormalized fallback is accepted. The pinned kernel and initrd
plus normalized rootfs total 1,651,772,096 bytes, within the 1600 MiB immutable image
ceiling; staging still checks the actual prepared bytes. Official HTTPS checksum consistency and the
independently reviewed repository archive digest remain mandatory. A failed preparation removes the stale
`env.sh` success entry point and does not publish the failed normalized copy.
Each validator has a 4 GiB Nexus disk budget: 1 GiB for Kura, 512 MiB for
snapshots and 2.5 GiB for SoraFS, plus an explicit 256 MiB encoded WSV memory
budget. SoraFS retains both the 1600 MiB guest ceiling and the 512 MiB compressed
bundle ceiling, leaving 448 MiB for discovery, manifests and storage metadata.
The shared policy requires at least 64 MiB of that headroom. The startup probe
derives matching QEMU and cgroup geometry from the selected host CPU/RAM ceiling,
including VMM overhead.

The signed validator units must bound each validator process to 1000 millicores
and 2 GiB RAM separately from its Inrou worker. Four validators and workers plus
1000 millicores/2 GiB for the guest OS require 9 CPUs and 13 GiB RAM; a 16 GiB
Linux guest leaves 3 GiB additional guest headroom. These are allocation bounds,
not performance qualification or a physical RAM reservation. Full disk budgeting
must include all four root volumes, all four immutable image copies, app-data
and Nexus caps (28.5 GiB combined at the admitted guest-image ceiling), guest OS,
signed release/upload artifacts, preparation copies, staging and filesystem
overhead. The 16 MiB temporary filesystem per replica is RAM-backed. Size the
physically backed guest disk from the exact admitted canary, all retained copies
and full runtime/Nexus growth allowances. A 64 GiB disk provides headroom; a
smaller disk requires measured free bytes and artifact sizes demonstrating that
all owners fit with an explicit operating reserve before native preparation.
The retained original assets plus workspace, local-stage and host-stage guest
copies are additional to the 28.5 GiB runtime allowance.
Expand and qualify the actual guest only through the reviewed deployment
procedure; never use compressed size or sparse current usage as the permitted
full growth budget.

Public-reset V1 supports exactly one Linux/AArch64 host running all four
validators and the edge. Inventory admission rejects a dedicated edge or any
validator on a different authenticated SSH host-key identity before opening
deployment credentials or materializing artifacts. The host dispatcher applies
the same admission before accessing guards or mutating host state. This single
host holds the common lock and durable progress record for all mutation phase
boundaries; distributed placement is not an admitted architecture.

Provision all four locked execution identities on that host and assign distinct
canonical slots to the validators. Each of the five role endpoints retains its
own exact DNS alias and guarded service/state roots, uses root on SSH port 22,
and pins the same actual ssh-ed25519 host key through its exact known-hosts line.
Distinct DNS aliases do not establish independent hosts. Never invent host-key
identities or copy a host private key to make separate machines appear cohosted.
These accounts are execution identities only; the command does not provision
accounts or persist deployment credentials.

### Prepare the fixed Inrou host runtime

On each native AArch64 Linux validator, install packages that provide
root-owned, single-link executables at these exact paths:

- `/usr/bin/qemu-system-aarch64`
- `/usr/bin/setpriv`
- `/usr/bin/ldd`
- `/usr/bin/bwrap`
- `/usr/bin/nsenter`
- `/usr/bin/socat`

QEMU must implement `-run-with exit-with-parent=on`; the stock Debian 13
QEMU 10 package lacks this required lifecycle capability. With the official
`trixie-backports` APT source enabled, install the supported QEMU packages
before packaging the closure:

```bash
sudo apt-get update
sudo apt-get install -t trixie-backports qemu-system-arm qemu-utils
```

The packager probes the exact executable with `-run-with help` and requires
`exit-with-parent=<bool (on/off)>` before publishing the immutable closure.
An older package must be upgraded; keep the lifecycle option enabled. Run this
host dependency preparation before starting a release build or rollout.

QEMU, `setpriv`, `ldd`, `bwrap`, and `nsenter` must be direct files. The `socat`
entry may resolve through package-managed symlinks. The QEMU and `setpriv` ELF
interpreters and dynamic-library closure may use merged `/usr` and alternatives
links; every traversed link and directory must remain root-custodied, and the
resolved files must be singly linked and non-writable by group/other. The
packager copies their bytes to the exact paths requested by the executables;
its output and destination contain no symlinks. Create the fixed parent once,
then run the packager from the `optimizations` checkout as root:

```bash
sudo install -d -o root -g root -m 0755 /opt/iroha
sudo -- python3 scripts/ci/package_inrou_runtime_v1.py
```

The packager has no destination option. It atomically creates the previously
absent `/opt/iroha/inrou-runtime-v1/` with `root/` and `manifest.sha256`, and
fails if that destination already exists. Its only source overrides are
canonical absolute `--qemu`, `--setpriv`, and `--ldd` paths; this Taira AArch64
posture uses the defaults.

The daemon startup boundary additionally requires direct root-custodied
`/usr/bin/qemu-img`, one root-custodied `iptables` executable at
`/usr/sbin/iptables`, `/sbin/iptables`, `/usr/bin/iptables`, or `/bin/iptables`,
`/dev/kvm` with API version 12, and unified cgroup v2 with the `cpu`, `io`,
`memory`, and `pids` controllers available. Kernel namespace, QEMU user-network
listener/private-connector, QMP, firewall owner-match, and cgroup controls are
exercised by the bounded startup probe; `up` fails closed if any is unavailable.
This artifact-free probe does not boot a guest or verify the workload loopback
bridge.

The daemon creates non-root Inrou lease disks at the admitted exact byte length
and binds them to the service placement and authoritative generation. On first
initialization, the guest checks the device and filesystem signature, formats a
blank device as ext4 with the expected deterministic UUID, and verifies its mount
identity and hardened options. The current runtime does not impose a 128 MiB
volume multiple or a host-side fixed ext4 feature profile. The selected 64 MiB
app-data volume must pass actual guest format, write and restart qualification.

Every successful run must prove a real guest launch, four placements, and the
public route. Prepare verified AArch64 assets, generate the exact deploy
workspace with the same-revision compiled CLI, and pass that workspace to the
devnet:

The asset preparer uses the fixed official HTTPS URL for the repository-pinned
Debian build. It permits only the observed single HTTPS redirect to
`laotzu.ftp.acc.umu.se` at the identical path; source overrides, other mirror routes,
credentials, query/fragment changes and redirect loops are rejected. The repository
SHA512 archive pin is the authority: the official `SHA512SUMS` must contain exactly one
matching entry, and the downloaded archive must match the same pin before any
extraction. Debian's current cloud-image pipeline does not publish detached
signatures; no GPG keyring or signature fallback is used. See the
[official cloud-image verification guidance](https://cloud.debian.org/images/cloud/)
and [Debian's signing clarification](https://lists.debian.org/debian-cloud/2022/08/msg00010.html).
The independently signed Taira release and owner authorization remain required.

```bash
TAIRA_RUST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
cargo build --locked --profile local-release --target "$TAIRA_RUST_TARGET" \
  -p iroha_cli --bin iroha

eval "$(python3 scripts/ci/prepare_inrou_portable_guest_assets.py \
  --output-dir /private/runtime/taira-inrou-assets \
  --print-env)"

target/"$TAIRA_RUST_TARGET"/local-release/iroha taira inrou-workspace \
  --kernel "$IROHA_INROU_PORTABLE_KERNEL_IMAGE" \
  --rootfs "$IROHA_INROU_PORTABLE_ROOTFS_IMAGE" \
  --initrd "$IROHA_INROU_PORTABLE_INITRD_IMAGE" \
  --output-dir /private/runtime/taira-inrou-canary \
  --json

python3 scripts/taira_devnet.py up \
  --inrou-canary-dir /private/runtime/taira-inrou-canary
```

The `--output-dir` must not exist: `inrou-workspace` creates one direct,
effective-user-owned mode `0700` directory and never reuses it. It emits only
the exact deploy-mode `container_manifest.json`, `service_manifest.json`, and
deterministic embedded-Python `bundle.tgz`, plus mode `0700`
`inrou/aarch64/` directories containing direct, single-link mode `0600`
`vmlinux`, `rootfs.ext4`, and `initrd.img` copies. Every emitted file is
effective-user-owned mode `0600`. The compiled generator validates the final
bundle with the canonical Taira canary validator before reporting success.

Keep both asset and canary directories runtime-only, outside the repository
and disjoint from the disposable `--dir` tree and qualification Cargo target.
Every canary-path ancestor must be direct, owned by root, and non-writable by
group/other. Do not substitute generated fixtures, fallback filenames, or
placeholder guest images. The devnet rejects symlinks, empty files, permissive
modes, extra or missing tree members, oversized assets, and workspace overlap
before it mutates its managed tree. It pins every file identity and SHA-256,
revalidates the workspace before replacing the cohort, copies it through
no-follow descriptors into an owner-only network-local snapshot, and makes the
compiled stager consume only that snapshot. The final JSON reports the
aggregate `inrou_canary_input_content_sha256` without exposing input paths.

The mandatory path builds `sorafs-node`, invokes the compiled
`iroha taira inrou-stage --mode deploy --bind-validator-config-dir ...`, and
verifies both its exact owner-only stage and the four typed daemon configs it
rewrote. The command rejects any pre-existing Inrou table; there is no Python
TOML writer, idempotent reuse, or compatibility binding path. Before starting
a validator, it preseeds the service bundle, guest
directory, and public discovery commitments into each of the four disjoint
generated SoraFS roots. After signed finality and the four
MCP checks, the coordinator executes four prepared Inrou children in order:
`bundle-pin` (`inrou_bundle_pin`), `guest-pin` (`inrou_guest_pin`),
`discovery-pin` (`inrou_discovery_pin`), then `service-mutation`
(`inrou_canary`). Each invocation selects exactly one child and one of
prepare, retained-envelope submit, or read-only recovery. The coordinator
atomically persists the canonical authorization-bound envelope before one
submit, never replaces first-wins bytes, and requires exact Applied predecessor
evidence before preparing the next child. The final service mutation proves
exactly four active host adverts, four hosted replicas, the canonical
authoritative route, and four distinct routed replica identities. The final
JSON reports a redacted `inrou_canary` outcome; it never reports the stage path
or copies credentials into repository files. A successful report always sets
`inrou_guest_workload_qualification` to `verified`; there is no startup-only
success shape. It atomically publishes an owner-only exact-schema
`inrou_guest_qualification.json` record inside the disposable network for
subsequent read-only checks. That record binds the exact qualifying CLI path,
digest and byte length plus the source revision and native target triple. The
report also uses
`configured_inrou_vm_capacity_per_peer` and
`inrou_startup_boundary_qualified_peers` for the separately proven startup
boundary.

Each of those four hosted replicas receives its own root and non-root lease
disks. The canary does not share or multi-attach a disk between replica slots,
and common filenames or matching guest paths are not evidence of shared
storage.

There is no external signed release ceremony, evidence archive, promotion
state, 24-hour soak, host service installation, or predecessor rollback in
this disposable path. `up` records a stable in-run worktree observation and
binds the exact binaries it executes, but reports Cargo source consumption as
`not_proven`.

## Daily commands

Inspect the running cohort without writing to it:

```bash
python3 scripts/taira_devnet.py check
```

`check` binds the listeners to the generated Taira chain, genesis hash,
loopback ports, and four exact owner-only `peerN.process.json` V1 identities.
Each identity pins the Linux boot, process start time, executable path/device/inode,
exact argv/config, UID/GID, session, and process group; unrelated services or a
reused numeric PID cannot satisfy it. It reads the Torii base port from the generated
`client.toml`, so an `up` started with a custom `--base-api-port` needs no
repeated port argument. It also requires and strictly validates the owner-only
V1 guest qualification record, including the canonical four-replica canary
receipt and input digest. It rehashes the retained input snapshot, requires the
recorded `optimizations` revision and Linux/AArch64 target on every validator,
rehashes and executes only the recorded qualifying CLI, revalidates the exact
retained stage, and invokes one `iroha taira inrou-check --mode deploy`. The
compiled check performs an account-signed status read, compares the live
container and service manifest hashes with the stage, and observes all four
route identities. The report labels the historical mutation result
`inrou_stored_deploy_receipt` and the current result `inrou_live_check`; it
never presents the stored receipt as fresh evidence. It remains read-only: it
does not repeat KVM qualification, submit a ping, register an artifact, or
submit a canary deployment.

Stop it and destroy the complete generated network:

```bash
python3 scripts/taira_devnet.py down
```

Every `up`, `check`, and `down` holds one exclusive lock on the managed marker.
Taira lifecycle control is Linux-only and requires native `pidfd_open`,
`pidfd_send_signal`, pollable pidfds, and procfs. Startup, restart, inspection,
and teardown reopen and hold a pidfd before observing or signaling a process;
signals and exit waits use only that pidfd. There is no `ps`, PID signal, or
shell-kill fallback. Bare `peerN.pid` files are retired and rejected without
migration. Teardown returns success only after every exact process record and
matching process is gone and the pinned cleanup-directory identity is unchanged. It
atomically moves that exact inode to a private cleanup name, proves the identity
again, then removes configs, logs, state, runtime signers, and onboarding
material together. If either proof fails, the bundle (or quarantined racing
replacement) is retained for diagnosis and the command fails instead of
deleting unproven ownership evidence.

Optionally run the broader read-only public-product route diagnostic after the
standard signed smoke and four-peer MCP checks:

```bash
python3 scripts/taira_devnet.py up \
  --inrou-canary-dir /private/runtime/taira-inrou-canary \
  --full-doctor
```

`--full-doctor` runs the same-revision `iroha taira doctor` against the
generated local endpoint after the mandatory real Inrou canary. It adds the
broad public-product route diagnostic; it does not replace any guest workload
qualification step.

The optional local diagnostic is not public-ingress qualification and is never
a default devnet gate. Run the same-revision `iroha taira doctor` directly
against a public ingress when qualifying that deployment.

The dedicated daemon's config validation, help, and version commands are
offline introspection surfaces: they never open or consume the inherited
runtime-signer descriptor. Every node-starting invocation still requires the
exact descriptor and compiled Taira profile.

The output directory is owner-only and contains private keys and runtime
tokens. Never commit, print, upload, or archive it. On failure the command
prints bounded peer log tails, attempts bounded teardown, and destroys the
bundle after proving shutdown and directory identity. If either proof fails, it
warns and retains the complete bundle for operator diagnosis instead of
claiming cleanup.

## Public reset

The same-revision compiled CLI is the single public-reset path. Use the
[maintained release preparation](../../../docs/source/taira_release.md) for the
explicitly authenticated source and same-release artifacts. The CLI requires its
exact compiled commit and a clean `optimizations` source closure; routine
`local-fast-build` binaries cannot assemble release inputs.

Set `TAIRA_RESET_CLI` to the exact `path` in the completed authenticated
preparation's `[taira-check] isolated native artifact` JSON observation with
`selection: "iroha"` and `cargo_artifact.profile.test: false`. Retain that
observation and check its `sha256` and `size` against the selected file. The gate
keeps this owner-only host-native CLI snapshot after its checks. Its
`cargo_artifact.executable` is the mutable Cargo output, and selection `cli` is a
test harness; neither is the operator path. A resumed preparation can reuse its
native checks, so use the observation from the original successful check.
`result.json.artifacts` instead lists AArch64 Linux deployment binaries; it does
not provide a host-native CLI field. Do not infer an operator path from
`target/release/iroha` or substitute an unrelated diagnostic snapshot.

The following examples use the selected host-native CLI on the operator host.
Admit the complete input closure locally before the read-only host preflight:

```bash
: "${TAIRA_RESET_CLI:?Set this to the retained shipping-native iroha observation path}"
"$TAIRA_RESET_CLI" taira public-reset preflight \
  --inventory /private/runtime/taira-public-reset/inventory.json \
  --authorization /private/runtime/taira-public-reset/authorization.json \
  --trusted-public-key /private/runtime/taira-public-reset/trusted-public-key.json \
  --ssh-identity /private/runtime/taira-public-reset/id_ed25519 \
  --known-hosts /private/runtime/taira-public-reset/known_hosts
```

Before preflight, use the same compiled CLI to create the inventory and owner
signature locally. `assemble --intent PATH` accepts the closed
`iroha.taira.public-reset.topology-intent.v1` document with explicit approved
endpoints and host pins, target occupancy, previous genesis anchor,
source/artifact paths, onboarding request, faucet/fee intent, nonce and timeouts.
Computed release/config/artifact pins, administrator identity, and generated
beacon/supervisor plans are not intent fields. Native preparation derives them
from the actual inputs. Do not copy a predecessor's generated plans into the intent.
The required `qualification_scope` is `core_testnet` for basic Taira/BPNG
testing or `full_inrou` for the additional VM workload qualification. Core scope
runs the onboarding, faucet and write canaries during fresh beacon provisioning,
installs the certified session and all four providers, then checks convergence and
one validator restart followed by the same three canaries, and public Torii/MCP
checks. Inrou scope exercises all four restart waves and adds its four
prepared mutations and live workload checks. Inventory, authorization, journal
and report bind the same scope; recovery cannot change it. A core result does
not establish Inrou workload readiness. Both scopes retain the installation
barrier and host rollback plan; only full scope adds Preseed.
Render initial validator units using the authenticated same-revision
`scripts/taira_validator_unit.py`, then bind those bytes into the eight validator
artifact roles, including same-release Kagami. The separately rendered final
beacon units select `beacon.toml` and FD200 custody. Type=exec waits for the inline signer custody launcher; native
checks still require the actual daemon and readiness. Native assembly fills
derived hashes, sizes, modes, source/stage identities and validator fingerprints
from the actual files, then runs the existing admission checks.
Generate its source manifest with `"$TAIRA_RESET_CLI" taira public-reset
source-manifest --source-root DIR` from the exact clean `optimizations` checkout
with a direct `.git` directory. The build's read-only source capture has no Git
repository and is not this native source-manifest input. Taira's signed
genesis must use NPoS; each supplied validator config must bind that actual genesis
and its declared peer. Prepare the deploy-mode Inrou stage before assembly, since
staging binds the final validator config bytes. Core scope does not require an
Inrou stage. The separate maintenance administrator must already be registered
with `CanSetParameters` in the actual signed genesis, have an admitted validator
Torii origin, and be distinct from the canary, validator clients and HTTP operator.

Create a dedicated operator signer with the native command before materializing
validator configs. Its output contains only the public key and path; the new
private key is written with mode `0600` in an existing mode-`0700` directory
outside repositories and is never overwritten:

```bash
"$TAIRA_RESET_CLI" taira public-reset operator-keygen \
  --private-key-file /private/runtime/taira-public-reset/validator-operator.key
```

Native context derivation obtains the operator public key from this actual
private-key file; it is not a topology-intent field. For each retained validator
config, pass the same public key to native
`config-rebase --config-fd FD --expected-genesis-file OLD --genesis-file NEW
--operator-public-key PUBLIC_KEY --output FRESH_PATH`. The command enables
`torii.operator_signatures` and installs that exact dedicated allowlist while
preserving the other settings. The retained config enters through an inherited
read-only private descriptor. Assembly verifies all four validator configs and
the dedicated key against the inventory; account and validator keys are separate
credentials.

Seat the SORA Parliament in the generated network and re-sign its genesis
before anything consumes it ([SORA Parliament seating](#sora-parliament-seating));
`prepare-public-inputs` refuses a network whose validator profile or genesis
citizens cannot seat every Parliament body.

Prepare the complete public bundle and nonce-bound beacon inputs natively before
assembly. Paths are illustrative; use the approved release's actual generated
network and canary public key, with fresh outputs in an owner-only runtime
directory. The first command needs no topology or generated plan. Construct the
closed topology intent using the exact resulting `canary-onboarding-request.json`
and the independently selected topology before the second command:

```bash
"$TAIRA_RESET_CLI" taira public-reset prepare-public-inputs \
  --localnet-dir /private/runtime/taira-public-reset/network \
  --canary-public-key /private/runtime/taira-public-reset/canary/public.key \
  --output-dir /private/runtime/taira-public-reset/public-inputs
"$TAIRA_RESET_CLI" taira public-reset prepare-beacon-inputs \
  --intent /private/runtime/taira-public-reset/topology-intent.json \
  --public-inputs /private/runtime/taira-public-reset/public-inputs \
  --output /private/runtime/taira-public-reset/beacon-inputs.json
```

The five-file public bundle includes the raw `genesis.json` and its authenticated
manifest hash. Incomplete four-file bundles are rejected; prepare a fresh complete
bundle. The second command derives the request and four ordered final-unit inputs
from native-validated genesis and the intent's nonce. Use each returned
`credential_path` unchanged with the authenticated renderer's
`--global-beacon-credential` and `--config-file beacon.toml`, preserving the initial
unit's exact runtime-key and mint-finality-seed paths. Render four fresh mode0644
final unit files; do not modify the initial units or construct beacon request JSON
by hand. The [maintained retry caller](../../../docs/source/taira_retry.md)
authenticates the pinned renderer and initial units and performs these steps for
its admitted rolled-back deployment scope.

Assembly binds the four client configs and initial/final units in validator
order to the authenticated beacon inputs. Scheduling epochs retain the incumbent
mint-finality authority generation; no separate supervisor plan is installed.
This example uses `full_inrou`; omit `--inrou-stage-dir` for `core_testnet`.

```bash
reset_context_inputs=(
  --public-inputs /private/runtime/taira-public-reset/public-inputs
  --runtime-client-config /private/runtime/taira-public-reset/client.toml
  --validator-client-config /private/runtime/taira-public-reset/client1.toml
    /private/runtime/taira-public-reset/client2.toml
    /private/runtime/taira-public-reset/client3.toml
    /private/runtime/taira-public-reset/client4.toml
  --validator-operator-key /private/runtime/taira-public-reset/validator-operator.key
  --onboarding-token /private/runtime/taira-public-reset/onboarding-token
  --inrou-stage-dir /private/runtime/taira-public-reset/inrou-stage
  --validator-unit /private/runtime/taira-public-reset/initial-units/iroha3d-taira-validator-1.service
    /private/runtime/taira-public-reset/initial-units/iroha3d-taira-validator-2.service
    /private/runtime/taira-public-reset/initial-units/iroha3d-taira-validator-3.service
    /private/runtime/taira-public-reset/initial-units/iroha3d-taira-validator-4.service
  --edge-unit /private/runtime/taira-public-reset/edge.service
  --known-hosts /private/runtime/taira-public-reset/known_hosts
)
reset_local_inputs=(
  "${reset_context_inputs[@]}"
  --beacon-inputs /private/runtime/taira-public-reset/beacon-inputs.json
  --beacon-validator-unit /private/runtime/taira-public-reset/beacon-units/iroha3d-taira-validator-1.service
    /private/runtime/taira-public-reset/beacon-units/iroha3d-taira-validator-2.service
    /private/runtime/taira-public-reset/beacon-units/iroha3d-taira-validator-3.service
    /private/runtime/taira-public-reset/beacon-units/iroha3d-taira-validator-4.service
)
"$TAIRA_RESET_CLI" taira public-reset assemble \
  --intent /private/runtime/taira-public-reset/topology-intent.json \
  "${reset_local_inputs[@]}" \
  --output /private/runtime/taira-public-reset/inventory.json
"$TAIRA_RESET_CLI" taira public-reset authorize \
  --inventory /private/runtime/taira-public-reset/inventory.json \
  "${reset_local_inputs[@]}" \
  --trusted-public-key /private/runtime/taira-public-reset/trusted-public-key.json \
  --signing-key-fd 3 \
  --output /private/runtime/taira-public-reset/authorization.json \
  3< /private/runtime/taira-public-reset/owner-signing-key
```

Assembly independently rederives the context and validates the generated beacon
inputs and final units. These local preparation commands do not contact the named
hosts. Apply uses the admitted runtime inputs. Epoch retention observes finalized
workload blocks and does not create empty blocks.

Review the assembled inventory before authorizing it. `authorize` revalidates the
complete local inputs and signs the retained inventory file bytes; editing or
reformatting that file invalidates the signature. The independently trusted
`TrustedKeyV1` must match the inherited Ed25519 key. The key file must be a direct
owner-private single-link regular file (0400 or 0600), at most 512 bytes, containing
its Iroha private-key string with at most one trailing newline. No authority key is
generated or returned. Outputs are created as private files without replacement;
use fresh paths instead of overwriting prior inputs. Authorization lasts at most
15 minutes for admission, with the separate bounded execution lease computed by
the existing coordinator. Run read-only host preflight promptly after signing;
`apply` performs the live deployment changes.

`InventoryV1` must contain `canary_onboarding_request`; it is not optional and
has no derived-at-runtime fallback. The value must be the exact canonical
`AccountOnboardingPlanRequestV1`: version 1, the canonical domainless
single-signatory canary account, its deterministically derived rollout alias in
the `taira.universal` scope, and an empty `permissions` array. The inventory
SHA-256 covered by the signed authorization binds this complete request before
admission, so neither an operator nor a resumed controller can substitute the
account, alias, or permissions during prepare. Preflight rejects a missing,
noncanonical, mismatched, or permission-bearing request.

The inventory must also contain `faucet_policy` with the exact canonical
single-signatory faucet `authority`, resolved Base58 `asset_definition_id`, and
positive fixed `amount` from the rendered Taira configuration. The signed
authorization repeats and binds this policy. Prepared faucet envelopes are
accepted only when their signer, transfer asset, amount, fee closure, and
instruction bytes all match these independently admitted values; no value is
learned from the envelope being authenticated.

`iroha taira public-reset preflight` admits the signed local inputs and then
contacts all four validators and the edge through their exact pinned SSH endpoints
for read-only host admission. Run it from the Linux controller before `apply`.
It requires no canary signing config, onboarding token or runtime stage, and
creates no journal, host lease, lock, progress or durable receipt. Each host check
uses the signed install timeout. A failed host check fails the command and names
the target. `apply` repeats host preflight to detect changes since that check.
`iroha taira public-reset apply` is the live mutating operation. Apply requires
explicit owner-private, runtime-only authorization, SSH, and canary inputs. Each
forward apply and RestartProof recovery also requires `--validator-operator-key`
pointing at the same dedicated operator credential admitted during assembly.
The coordinator passes it to signed status children through a retained read-only
descriptor. Each
admitted host must already have the trusted compiled dispatcher and reset guard
provisioned independently of the candidate. The public coordinator requires the
actual cohort's exact durable Inrou preseed qualifications before startup, then
runs public canary and restart proofs. The disposable `local-release` devnet is a
separate development test command; it is not public-reset admission evidence or
a prerequisite to a fresh public reset. Never
persist those inputs in the repository, let the candidate bootstrap its own
host authority, or introduce a Python alias or parallel V1 schema.

The signed inventory requires an explicit `initial_state` on each validator
and edge. Its canonical JSON is `{"state":"vacant","value":null}` or an object
with `"state":"admitted_release"` and the release record in `"value"`. Both
fields are required; vacant state accepts only `null` content. Unknown fields,
unknown discriminators, and retired rollback shapes are rejected. There is no
implicit predecessor or legacy rollback field. An admitted release binds its
actual prior configuration commit, canonical `releases/<commit>` directory, and
exactly five ordered runtime artifacts: `iroha3d`, `config`, `genesis`,
`genesis_hash`, and `validator_unit`. Each artifact independently binds its source
revision, path, hash, size and mode; the daemon may come from a different pinned
release. Candidate validators still require all eight artifacts. Prior CLI/Kagami
for an occupied epoch supervisor remain pinned by that supervisor's own signed
plan, whose tool release is protected from cleanup alongside the validator roots.
Every occupied validator record also requires `service_state`: explicitly
`running` with null content, or `stopped` with the independently selected state
root's `device` and nonzero `inode`. Missing state has no default. Running requires
the exact live prior process; a failed probe never changes it to stopped. Stopped
requires the exact prior artifacts, loaded unit and selector, a terminal inactive
or failed unit with no job/PID/cgroup members or escaped state references, and the
signed state directory identity. This is occupied state, never vacancy or a claim
that the predecessor is healthy. A vacant
target still requires independent trusted dispatcher/guard provisioning,
Linux/AArch64, and validator KVM API 12; it requires no running predecessor.
The network's `previous_genesis_hash` remains the actual public reset anchor,
including when the admitted Linux target namespaces are new.

Vacant targets require an absent `current` selector, an empty root-owned 0700
state directory, an empty release namespace, and the exact signed systemd
unit loaded without drop-ins or pending reload. The edge additionally binds
`systemd_unit_sha256` for `/etc/systemd/system/nginx.service` and requires an
absent Taira route. The dispatcher checks inactive service/job/PID state,
empty cgroup membership, and bounded process/file/mount-namespace references
before accepting vacancy. Service, state, guard, and first-edge route roots
must share the filesystem used for atomic rollback quarantine.

The canonical plan starts all validators, runs native beacon bootstrap and
canaries, then convergence and restart proofs before staging and activating the
edge. The signed initial epoch must accommodate the actual execution blocks
before exact-height threshold-key installation and signer activation.
Native bootstrap records authenticated committed heights, including jumps
between useful operations. It never advances phases with empty blocks.
First edge activation
uses a durable start operation. A failed first installation stops its service,
restores the exact original empty state inode, removes only its admitted
selector, and atomically retains its candidate release/configuration in the
private authorization rollback namespace. It never starts a fictitious prior
release or deletes unproven state. Failure to prove ownership or shutdown
retains the evidence and leaves rollback incomplete.

An occupied reset atomically renames each complete prior state directory to
`<reset_guard>/rollback/<authorization_nonce>/state` on the same filesystem and
starts a fresh active directory from the approved new genesis. The archive is a
local retained tree, not an off-host backup or a migration of old ledger data.
Existing accounts, balances, aliases, contracts and catalog state remain in that
old chain unless explicitly included in the new genesis; the new network identity
requires new client/trust bindings. Keep the exact prior artifacts and archive.
Before deployment is proven, rollback restores the old directory inode, release
selector and unit. A signed running predecessor must restart and pass process
attestation; a signed stopped predecessor remains stopped with absence rechecked.
Restoring a failed predecessor does not repair it. Unresolved mutation outcomes
remain journaled, and a proven deployment proceeds through sealing/cleanup rather
than rollback. A reset requires explicit approval of this state replacement.

The rendered validator configuration must replace the dedicated
`REPLACE_WITH_TAIRA_CANARY_ONBOARDING_*` fields with one credential scoped to
the `universal` dataspace. Its token digest must match the owner-only token
admitted by the reset closure; the raw token never enters the release bundle or
repository.

## SORA Parliament seating

The SORA Parliament is the only SCCP governance authority
([`specs/sccp.md`](../../../specs/sccp.md) §4.14.5, §4.18): without a seated
Parliament no SCCP route can be registered, activated, paused or recovered, and
no other Parliament proposal kind can pass either. A fresh Taira therefore
seats the Parliament in genesis, and the reset tooling, `scripts/taira_devnet.py`
and `iroha taira doctor` refuse or flag a network that cannot seat it.

### Recommended profile

`config.toml` carries the recommended `[gov]` profile. It is part of the
consensus execution policy, so every validator uses exactly these values, and
`iroha taira seat-parliament` copies the seating keys into every generated
validator config before genesis is signed.

| Setting | Value |
|---|---|
| genesis citizens `C` | 16 |
| `citizenship_bond_amount` | 1 000 000 XOR (40 faucet claims) |
| `rules_committee_size`, `agenda_council_size`, `interest_panel_size`, `review_panel_size`, `coordination_council_size`, `mpc_committee_size`, `fma_committee_size`, `oversight_committee_size` | 5 each |
| `policy_jury_size` / `confirmation_jury_size` | 9 / 7 |
| `parliament_alternate_size` | 3 |
| `parliament_timed_ovn`: `max_corpus_entries`, `registration_phase_blocks`, `survivor_freeze_phase_blocks`, `commitment_phase_blocks`, `release_delay_blocks`, `opening_phase_blocks` | 16, 300, 100, 300, 50, 300 |
| `parliament_invitation_phase_blocks` / `parliament_public_finding_phase_blocks` | 300 / 900 |
| `min_enactment_delay` | 50 |
| `parliament_tle_key_lifecycle`: `max_fresh_ballots_per_session`, `session_lifetime_blocks` | 8, 7 200 |
| `[torii.faucet]` `pow_adaptive_claims_per_extra_bit` / `pow_adaptive_max_extra_bits` | 2 / 8 |
| `[torii.faucet]` `pow_max_anchor_age_blocks` / `pow_adaptive_lookback_blocks` | 6 / 64 |
| `gov.citizenship_escrow_account` | fresh per network, key discarded |

`mpc_committee_size` is not in the spec table; it follows the same five-seat
profile because validation-fee proposals also draw the MPC Committee. A Policy
Jury of at most 20 seats never needs a Confirmation Jury, and the fixed windows
of one round sum to about 1 104 blocks (about 74 minutes at 4 s per block)
before deliberation.

Adaptive faucet difficulty: the faucet pays 25 000 XOR at a 4-bit scrypt proof
of work (`log_n = 13, r = 8`, about 8 MiB and tens of milliseconds per
evaluation on a desktop core). Torii counts the claims committed in the 64
blocks that end at the claimant's chosen anchor, plus queued claims, and every
2 counted claims add one bit, up to 8 extra bits (12 in total). Because the
claimant chooses the anchor, the window only sees claims older than the anchor
age: under a 256-block anchor age a claimant pinning one old anchor would pay
the 4-bit base for every one of 40 claims (640 evaluations). Taira therefore
accepts anchors at most 6 blocks old (`pow_max_anchor_age_blocks = 6`, far
below the 64-block lookback):

- an occasional claim costs 2^4 = 16 evaluations, under a second on a desktop;
- the cheapest burst of the 40 claims of one citizenship bond, one claim per
  block with every claim pinned to the oldest accepted anchor, counts every
  claim more than 6 blocks old and costs 81 984 evaluations (8 claims at the
  base, then one extra bit per 2 counted claims up to the cap), roughly half an
  hour to an hour of one desktop core instead of 640 evaluations;
- the cap bounds an honest claim at 2^12 = 4 096 evaluations, a few minutes on a
  desktop core and longer on a phone. Iroha produces no empty blocks, so on an
  idle Taira the lookback can hold only faucet claims; a higher cap (for example
  16 bits) would then price every onboarding wallet out, which is why the cap
  stays at 8 extra bits;
- the trade-off of the short anchor age: a proof must reach Torii within 6
  committed blocks of its anchor, about 24 s while blocks come at the 4 s
  target and longer on a quieter chain. A base-difficulty proof finishes in
  about a second even on a phone; a slow solver near the cap during a burst may
  see its anchor expire and must fetch a fresh puzzle.

TODO(ws55): Torii's `faucet_pow_recent_claims` should count adaptive claims up
to the current committed height, not up to the claimant-chosen anchor; the
anchor age then stops mattering for the adaptive count.

### Refusal rules

`iroha taira seat-parliament`, `iroha taira public-reset prepare-public-inputs`
and `scripts/taira_devnet.py` refuse a network when:

- the eligible genesis citizens (bond at least `citizenship_bond_amount`) are
  fewer than the largest body a proposal can require (every public body and the
  Policy Jury);
- `policy_jury_size > 20` and `policy_jury_size > C - 3`;
- either jury is below the hidden-ballot anonymity floor of 3;
- `max_corpus_entries` is below the larger jury, or the registration window is
  not longer than `max_corpus_entries`, or the survivor-freeze window is shorter;
- the bond is within 40 faucet claims (`citizenship_bond_amount < 40 × amount`);
- adaptive faucet difficulty is off (lookback, claims per extra bit or maximum
  extra bits is zero) while the faucet is enabled;
- `pow_max_anchor_age_blocks` is not below `pow_adaptive_lookback_blocks`, or
  the cheapest 40-claim burst (every claim pinned to the oldest accepted anchor)
  costs no more than flat proof of work
  (`faucet_anchor_age_below_lookback`);
- `gov.citizenship_escrow_account` is unset, is the default governance account
  or any other account whose key ships in this repository (`defaults/`, the
  `iroha_test_samples` keys), or is not the fresh escrow the seating run
  generated (`citizenship_escrow_is_custodial`); anyone holding that key could
  drain every bond and register fully bonded Sybil citizens for free;
- `coordination_council_size` is unset (its default is 150);
- validators disagree on the seating profile, or genesis grants
  `CanManageParliament` (SCCP attempts need no clerk).

### Genesis citizens

`iroha taira seat-parliament` renders the citizens into the freshly generated,
not yet deployed Kagami network. `genesis.template.json` therefore carries no
`RegisterCitizen`: citizen accounts are runtime-generated, like the other
runtime signer identities, and never live in the repository. For each citizen
the command generates an Ed25519 key and appends to genesis `Register<Account>`,
a mint of the bond plus a fee float (1 000 XOR by default, for the ordinary
fees of invitations, endorsements and ballots) and
`RegisterCitizen { owner, amount = citizenship_bond_amount }`. The citizenship
escrow is fresh for every network: the command generates an Ed25519 key,
discards it without writing it anywhere, writes the account into every
validator's `gov.citizenship_escrow_account` next to the other seating keys and
registers it in the appended genesis transaction. No one ever needs that key:
core locks the bond into the escrow on `RegisterCitizen` and releases it on
unregistration itself. Kagami's default escrow is the governance account whose
private key is published in `defaults/client.toml`, and the sample escrow in
`config.toml` is an account with a published test key. The command grants the
genesis-only `CanProposeSccpRouteGovernance` only to the account of
`--sccp-proposer-public-key` (off by default for the public reset;
`scripts/taira_devnet.py` grants it to its client account). Nobody receives
`CanManageParliament`.

The keys are runtime secrets: the command writes them to a fresh owner-only
directory, by default `<network>/runtime/taira-parliament-citizens/`
(mode 0700), as `citizen-NN.private_key` and a matching
`citizen-NN.client.toml` (mode 0600 each), plus a public `citizens.json`
manifest that also records the citizenship escrow account. Each client config is the network's `client.toml` with the citizen's
public key, `account.private_key_file = "citizen-NN.private_key"` and
`network_id_file` set to the absolute path of `<network>/genesis.expected_hash`,
which re-signing rewrites. Hand each key to a distinct live participant, never
commit it, and destroy the directory with the network. Anyone can join later
with an ordinary `RegisterCitizen` at the configured bond.

The command edits `genesis.json` and the validator configs only; re-sign
genesis with the same-release Kagami before anything consumes it. Kagami never
replaces a different published network identity and `peer0.toml` still reads
the pre-seating one while signing, so publish the seated identity beside it and
rename it over the old one afterwards (`scripts/taira_devnet.py` does the same):

```bash
iroha --config <network>/client.toml taira seat-parliament --localnet-dir <network>
kagami genesis sign <network>/genesis.json \
  --private-key-file <network>/genesis.private_key \
  --config <network>/peer0.toml \
  --out-file <network>/genesis.signed.nrt \
  --bound-manifest-out <network>/genesis.json \
  --expected-hash-out <network>/genesis.expected_hash.next
mv <network>/genesis.expected_hash.next <network>/genesis.expected_hash
```

### Reset checklist

1. Before the reset, enact one Parliament proposal that pauses every live SCCP
   revision (`SetDestinationPaused`, `SetTairaPaused`) and apply the controls on
   the destinations (§4.18); plan for at least one Parliament round.
2. Generate the four-validator Taira network with Kagami, then seat the
   Parliament and re-sign genesis as above.
3. Continue with `materialize-validator-config`, `prepare-public-inputs`
   (which refuses an unseated network) and the rest of the public reset.
4. Distribute the citizen keys to distinct participants.
5. In the reset ceremony, install the global-beacon session and the first
   Parliament TLE session and keep every validator's beacon and TLE signers
   running (§4.14.5 items 5 to 7). TODO(ws55): the in-node beacon/TLE DKG
   automation and node-generated credentials replace the manual ceremony.
6. Run the Parliament driver from a funded account, with one `--release-peer`
   per validator Torii root:
   `iroha --config <client.toml> sccp governance drive --release-peer <torii-1> ... --release-peer <torii-N> [--relay-dir <dir>]`.
   Keep it running while any SCCP proposal is Proposed or any attempt is
   active (§4.14.5 item 4). The driver does not vote; citizens cast their own
   ballots (`scripts/taira_devnet.py citizens` acts for the genesis citizens on
   devnets, see [Devnet citizens](#devnet-citizens)).
7. Check the result with `iroha taira doctor --parliament`.

### Doctor

`iroha taira doctor` always runs two checks over the compiled canonical
profile, named so that they cannot be read as live evidence and carrying an
exact detail that says the live values are not verified:
`canonical_bond_faucet_reach` (the live faucet amount against the compiled
citizenship bond) and `canonical_profile_seating` (the compiled canonical
profile against every static rule above; the escrow rule applies to generated
networks, since seating replaces the checked-in sample escrow). A Taira still
running an older live `[gov]` profile passes both. The live bond, escrow,
timed-OVN windows, `max_corpus_entries` and body sizes are served by
`/v1/gov/capabilities`, but that route is account-signed, Torii rejects an
unregistered signer, and the doctor deliberately loads no signing identity.
`--parliament` therefore adds one warning for each live requirement: the
eligible citizen census against every body size, the live `[gov]` profile,
escrow and adaptive faucet policy, the global-beacon session and roster, and
the Parliament TLE session with its remaining fresh-ballot capacity and
lifetime. TODO(ws35): a signer-free Parliament readiness projection turns these
into live checks. TODO(ws42): the doctor does not yet report SCCP attempt
progress (next due checkpoint, last progress, tip growth).

### Devnet citizens

`scripts/taira_devnet.py up` seats the Parliament automatically (sixteen
citizens, the genesis-only `CanProposeSccpRouteGovernance` for the devnet client
account) and reports the seating under `parliament`; `check` revalidates it. The
`citizens` subcommand acts for the genesis citizens through `iroha gov
parliament`, each with its own generated client config:

```bash
python3 scripts/taira_devnet.py citizens list
python3 scripts/taira_devnet.py citizens respond-invitation --iroha <iroha> \
  --governance-attempt-id <hex> --election-attempt-id <hex> --body policy-jury
python3 scripts/taira_devnet.py citizens endorse --iroha <iroha> \
  --governance-attempt-id <hex> --body-instance-id <hex> --result-root <hex>
python3 scripts/taira_devnet.py citizens ballot-register --iroha <iroha> \
  --ballot-attempt-id <hex> [--anchor-height <height>]
python3 scripts/taira_devnet.py citizens ballot-cast --iroha <iroha> \
  --ballot-attempt-id <hex> --choice approve
python3 scripts/taira_devnet.py citizens ballot-dropout --iroha <iroha> --ballot-attempt-id <hex>
python3 scripts/taira_devnet.py citizens ballot-status --iroha <iroha> \
  --governance-attempt-id <hex> [--ballot-attempt-id <hex>]
```

The actions map to `iroha gov parliament respond-invitation`, `endorse` and
`ballot register|cast|relay|dropout|status|anchor`; each helper first proves the
compiled CLI exposes the documented command and options and fails with a clear
message otherwise. Every action runs for all citizens unless `--citizen N`
selects some, and reports each citizen's result, since only drawn or seated
citizens can act. Ballot keys live next to the citizen keys
(`citizen-NN.ballot.key` and `citizen-NN.ballot-state.json`); a new state file
is pinned to the finality anchor the devnet's own Torii serves at the current
height (every devnet peer is operator-owned; public citizens compare the anchor
with a source they trust). `ballot-cast` writes each public ballot record to
`citizen-NN.ballot-<ballot>.record` and relays the records of citizens whose
predecessors in the frozen survivor order had not cast yet.

### Residual Sybil risk

Citizenship is only as scarce as test XOR. The bond of 40 faucet claims and the
adaptive faucet raise the cost of a burst-farmed citizen to about 82 000 scrypt
evaluations, but a patient claimant who waits for the lookback to move past
earlier claims (or fills it with cheap transactions of its own) pays the base
difficulty, any holder of test XOR can transfer it, and
citizens that accept seats and stay silent can stall every round, pauses
included (§9.13). Proof of work is a speed bump, not an identity: treat the
Taira Parliament as a test of the governance machinery, not as a Sybil-resistant
body. All genesis citizens are provisioned by the reset operator,
so until they are handed to independent participants the effective governance
trust is that operator (§9.1). The citizenship escrow itself is custody-grade:
seating gives every network a fresh escrow whose key no one holds. The other
governance custody accounts (`bond_escrow_account`, `slash_receiver_account`
and the viral-incentive accounts) still name the published sample key in
Kagami's profile; they hold no citizenship bonds, but anyone can move what
reaches them. TODO(ws55): give them fresh keyless accounts too.

## Public Taira endpoint checks

The compiled CLI owns the current public API contract. Build it from the same
revision being deployed. The read-only doctor deliberately does not load a
client config or signing identity:

```bash
cargo build --locked --profile release -p iroha_cli --bin iroha
target/release/iroha \
  taira doctor --public-root https://taira.sora.org --json
```

The public doctor defaults to `--scope basic` for essential network and MCP
connectivity. Valid local-clock fallback is reported as a warning; malformed
time or MCP responses fail. `--scope full` adds advanced product readiness and
synchronized-time requirements. Public-reset selects the doctor scope from its
signed qualification scope.
The public doctor remains non-mutating and does not impersonate an operator.
It requires the exact two-field operator-signature `401` from
`/v1/sumeragi/status` and, in full scope, the exact two-field canonical-account
`401` from `/v1/soracloud/status`; arbitrary gateway challenges fail closed. Exact runtime
topology and four-replica Inrou convergence belong to the signed Inrou canary,
not the public route-posture probe.

The Taira rollout asset is Digital Shekel `7ZepsJTHCVLKsrFFNZGSRGZgvBhv`
(`ds#boi.is`, scale 2); XOR `6TEAJqbb8oEPmLncoNiMRbLEK6tw` (scale 9) remains
the transaction-fee asset.

The offline `taira inrou-stage` command assigns the canary an immutable
`artifact-<digest>` service version derived from the complete canonical bundle
with only the version field cleared. Final guest publication references are
therefore part of the revision identity. A staged directory and receipt bind
the service manifest, container manifest, materialized bundle, and both SoraFS
manifests; changing any input produces a different revision. Its required
`--bind-validator-config-dir` must name the owner-only directory containing
exactly `peer0.toml` through `peer3.toml`; all four base configs must be fresh,
must match the staged placement set, and must not already contain an Inrou
table.
`--sorafs-retention-epoch` is a required nonzero absolute Unix-second boundary;
the receipt and both manifests bind it exactly, and a retry must reuse the same
value to reproduce the original manifest digests. Every manifest carries that
same value in both the pin policy and its sole metadata entry,
`soracloud.retention_epoch=<epoch>`; extra metadata is rejected. A retry reuses
an exact `Approved` record, waits for an exact `Pending` record, and registers
only a `Missing` record.

The signed `taira inrou-canary` mutation path checks authoritative SoraCloud
state before publishing either staged SoraFS manifest. `deploy` requires the
service to be absent. `upgrade` requires it to exist at a different immutable
revision; replaying the current staged revision fails before upload. That
preflight produces a mandatory signed compare-and-set condition: deploy binds
service absence, while upgrade binds the exact current version, service and
container manifest hashes, positive process generation, and the current config
and secret generations. The ledger checks the condition atomically in the same
transaction that admits the new revision, so revision or material drift after
preflight cannot become a lost update. Process, config, and secret generations
use checked monotonic increments; an exhausted counter fails closed and never
wraps or saturates into a replayable token.

An Inrou upgrade is an atomic 100% revision replacement. It cannot supersede an
active rollout or change the service execution plane, container runtime, or
route identity. The admitted revision becomes the sole current revision; no
baseline, split-traffic, rollback-serving, or other compatibility revision is
kept active.

After the explicit mutation, convergence requires the exact current/latest
version, both staged manifest hashes, four placements, and a positive process
generation on every status poll. A failed or changed status generation discards
all collected route evidence. Each accepted health response must also carry Torii-owned
served-service, served-version, replica-slot, process-generation, and
materialized-bundle headers. Torii only stamps those headers for an
authoritatively healthy placement whose host capability is valid, unexpired,
and matches the validator, peer, backend, and guest ISA, and whose exact bundle,
generation, and snapshot peer identity match the node-local process. Local-only
health or an expired host advert never substitutes for authoritative state.
Both local and remote ingress overwrite upstream values, so guest self-reporting
or a stale process cannot satisfy the proof.

An explicitly authorized public write canary is an ordered durable protocol,
not a one-shot command. `iroha taira public-reset apply` prepares, privately
persists, submits, and recovers the `onboarding`, `faucet`, and `final-canary`
children in that order. The low-level `iroha taira write-canary` command accepts
one child and one of `--prepare-envelope`, `--submit-prepared-envelope-fd`, or
`--recover-prepared-envelope-fd`; later preparation also requires the exact
Applied predecessor envelope. Do not invoke it manually unless implementing or
auditing that coordinator protocol. Keep the populated example client config
and owner-only onboarding-token file in the admitted runtime workspace.
The faucet child additionally requires `--faucet-authority`,
`--faucet-asset-id`, and `--faucet-amount`; these must come from the signed
inventory and never from a prepared response.

Do not persist signing keys, onboarding tokens, bearer tokens, or forwarded
authorization headers in this repository.

## Retained source-coupled assets

- `config.toml` and `genesis.template.json` are canonical profile sources
  consumed by compiled Kagami/config/genesis tests. The genesis source omits
  operator-owned mint-finality authority and the runtime-generated Parliament
  citizens, is not a raw or signable manifest, and is not an input to the
  disposable generator. `config.toml` is also the compiled source of the
  Parliament seating profile used by `iroha taira seat-parliament` and
  `iroha taira doctor`.
- `privacy_bootstrap_plan.json` and `privacy_rollout_plan_v1.json` remain
  coupled to Kagami's compiled privacy bootstrap feature. Kagami emits one
  height-1 template of twelve ordered registration/explicit-activation pairs,
  with no activation notice or observation-height delay. The template remains
  unexecuted until an authorized governance transaction applies it. The rollout
  carries no caller-authored assurance or availability claims. It proceeds
  only when the authenticated committed Exact12 manifest reports every one of
  the twelve rows as `production-qualified`; missing release, audit, security,
  or deployment evidence therefore halts rollout.
- `dns_records.json`, `explorer.runtime-config.json`, `sorafs_sites.json`, and
  `taira-canary-client.example.toml` describe the live public profile. The
  Explorer runtime config carries the exact genesis-derived `NETWORK_ID`, the
  fixed public Torii origin, and `toriiForceBaseUrl: true`; retired feature
  flags are not accepted by the first-release Explorer.
- `validator_roster.example.toml`, the edge renderer, nginx template, and edge
  installer remain the public-ingress configuration surface. The production
  `taira-explorer.sora.org` TLS vhost serves only the Explorer release symlink
  at `/Users/administrator/dev/iroha2-block-explorer-web/dist`; it does not
  proxy `/status` or `/v1`. Both Torii CORS and the public-edge CORS map admit
  the exact `https://taira-explorer.sora.org` browser origin.

The edge renderer's `--validator-listeners-only` scope emits only the four peer
upstreams and TLS listeners. It requires explicit `--validator-listen-address`
IP literals and existing `--tls-certificate` / `--tls-certificate-key` paths;
it does not infer TLS options or change the separately managed public routes.
Verify assigned interfaces, each forwarding socket's validator binding and the
complete candidate with the serving host's native nginx before activation.
This scope preserves the signed request URI and does not install or reload nginx.

For an edge on a separate native host, `--private-backend-listeners-only` emits
four unchanged-URI HTTP listeners at the explicit RFC1918
`--backend-listen-address` and consecutive `--backend-port-base` ports. It
requires `--backend-trusted-edge-address`, admits only that source, and retains
the caller headers sanitized by the TLS edge. The roster must select four exact
loopback Torii upstreams. Verify both hosts' interface/socket identities and
native nginx admission before activating either scope.

The edge installer validates with the fixed production executable
`/usr/sbin/nginx`. Dry runs may run unprivileged; installation and reload must
run as root into a root-owned include directory. Installed configuration is
published atomically as root-owned mode `0644`. Install and reload runs hold an
exclusive owner-only `.taira-edge-install.lock` in that directory for the full
render, validation, publication, reload, and rollback transaction. The installer
validates a private snapshot, requires the published bytes to match that exact
fingerprint, and rechecks content and metadata before and after live validation
and reload. Rollback never overwrites a changed target; it retains the
owner-only recovery copy for explicit operator handling. Executable overrides
and Homebrew-specific target discovery are intentionally not supported.

The retired Python reset, release, evidence, host-supervision, and soak
controllers are intentionally gone. The compiled `iroha taira public-reset`
preflight/apply pair is the sole reset surface; there is no compatibility alias
or parallel schema. Keep `scripts/taira_devnet.py` limited to disposable
process orchestration and end-to-end smoke verification.
