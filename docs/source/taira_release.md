# Local Taira release preparation

Build the four AArch64 Linux executables and capture read-only copies through
one maintained command. `prepare` always records build-only evidence and runs no
regression checks. Optional Basic, Full and focused diagnostics use `check`; none
is a deployment prerequisite for Taira or production. This replaces per-release
local build and capture scripts. Python 3.11+, Git, the repository Rust toolchain,
cargo-zigbuild, Zig and an existing warm Cargo target directory are required.
Native checks also require executable `lsof` at `/usr/sbin/lsof` on macOS or
`/usr/bin/lsof` on Linux. Both full and focused gates reject a missing or
nonexecutable inspector before compilation; install this prerequisite first.

Both doctor scopes require `GET /readyz` to return HTTP 200 with the exact
plain-text `Ready` response. A healthy status or mounted MCP route does not
substitute for admission readiness. Failed readiness reports only a bounded
machine error code; arbitrary upstream message or data fields are omitted.

The compiled `iroha taira doctor` checks `GET /v1/accounts/faucet/policy` in
both basic and full scopes without a client configuration or authentication.
A successful response must contain the exact canonical V1 policy. Missing
routes, malformed policies, unrelated forbidden responses and upstream failures
fail the check. The explicit disabled-faucet response produces a warning that
funding is unavailable; public-reset qualification still requires an enabled
HTTP 200 policy. Discovery does not establish signing trust: funding operations
continue to require independently trusted issuer and issuance inputs.

Run optional native diagnostics:

    python3 scripts/taira_release.py check

For an ordinary Mac client using a reviewed signed `optimizations` revision,
select exactly one client. A DPN CLI fix builds only `iroha`; select `musubi`
for the Musubi client:

    python3 scripts/taira_release.py prepare-client \
      --bin iroha \
      --expected-commit FULL_SIGNED_COMMIT \
      --expected-signer FULL_SIGNER_FINGERPRINT \
      --output-dir /absolute/iroha/target/client-observations/ATTEMPT

This command creates the owner-private `target/taira-macos-client` lane after
signed-source admission on first use, then reuses it. The separate fixed lane
uses the existing signed Git-object capture and source/
Cargo locks, the captured Rust toolchain, Apple linker and native jobserver. It
excludes worktree edits and inherited compiler hooks. `request.json`, the Cargo
JSON log and `result.json` bind the commit, source snapshot, compiler/linker and
selected package, exact Cargo binary emission and copied executable hash. Run
the retained `bin/iroha` or `bin/musubi` executable for the public workflow;
its package-version display alone does not prove source identity. This is an
ordinary client build, with no network, keys, deployment or qualification step;
Client selection does not compile the validator runtime. Musubi remains outside
the four-binary validator import contract. Existing
outputs are never replayed or overwritten. On failure, inspect the retained log
and select a fresh observation directory while reusing the same Cargo lane.
The native capture retains each original Cargo file and exclusively created copy
until its read-only `bin/` directory is published. Identical replacement bytes
cannot replace either admitted inode. Outputs cannot enter either fixed native
Cargo lane.

For the native Mac runtime used by host custody and deployment tools, build the
standard `iroha`, `kagami` and `iroha3d` together from the reviewed signed revision:

    python3 scripts/taira_release.py prepare-native-runtime \
      --expected-commit FULL_SIGNED_COMMIT \
      --expected-signer FULL_INDEPENDENT_SIGNER_FINGERPRINT \
      --output-dir /absolute/iroha/target/native-runtime-observations/ATTEMPT

This command creates the owner-private `target/taira-macos-runtime` lane on first
use after signed-source admission, then retains and reuses it. Its single locked,
offline release Cargo invocation selects the exact packages `iroha_cli`,
`iroha_kagami` and `irohad`, with their standard features and native macOS target.
It uses the captured toolchain, Apple's linker and Cargo's native jobserver;
worktree edits and local-fast source metadata never enter the build. Failed
requests and Cargo logs remain available. All three native executable identities
and digests must pass before the complete read-only `bin/` directory is published
atomically, followed by `result.json`; a failed attempt has no successful receipt.
Choose a fresh output for a retry while preserving the same Cargo cache.

The retained executables have mode0500. A native installer must independently
admit their source and digests and establish its required mode0755 custody; this
builder installs no dispatcher and changes no service. Its `qualified=false` and
`deployed=false` receipt records authenticated build inputs and outputs. The
unsigned build observation itself does not grant release authority or replace
the signed deployment and readiness checks. `prepare-client --bin iroha` and
`prepare-client --bin musubi` build one ordinary client in the separate client
lane.

Linux development checks default to the installed LLVM 18 compiler and linker;
macOS keeps the system Apple linker. Linux requires executable
`/usr/bin/clang-18` and `/usr/bin/ld.lld-18`. Missing or nonexecutable tools fail
before compilation, with their exact paths in the diagnostic. Install `clang-18`
and `lld-18` with the platform package manager first; there is no automatic
fallback. To diagnose with the system linker explicitly:

    python3 scripts/taira_release.py check \
      --target-dir /absolute/existing/development-lane \
      --native-linker system

The runner verifies `/usr/bin/clang-18` and `/usr/bin/ld.lld-18` against their
fixed canonical installation paths, checks executable custody, and reports
their paths and SHA256 digests. The standalone `scripts/taira_release_check.py`
entry point accepts the same option. Switching from `system` to `llvm`
invalidates Cargo fingerprints and can rebuild dependencies once in the
existing warm lane; keeping the same selection reuses that cache. Switching
back invalidates it again. Linker timing alone does not establish end-to-end
build or release qualification time.
`llvm` is rejected on macOS. Authenticated `prepare` accepts the same
`--native-linker` selection and binds the resolved compiler/linker paths, bytes
and native environment into its request. Resume revalidates those identities.
The native selection is independent of the explicitly pinned Zig shipping tools.

For a diagnostic that must survive its launching terminal or tool session, supply a
fresh absolute session path (it must not already exist):

    python3 scripts/taira_release.py check \
      --session-dir /absolute/private/check-20260922
    python3 scripts/taira_release.py check-status \
      --session-dir /absolute/private/check-20260922

`check` returns after starting a detached worker. The worker runs the same check
and owns `check.log`, a canonical `request.json`, `started.json`, and a final
`result.json` in a new 0700 directory. Records are 0400 and the log is 0600. The
request records diagnostic options, not the inherited environment or credentials.
`--focus-regression`, `--native-check-scope`, `--native-linker` and the existing
warm-lane selection work the same way in background mode.

`check-status` prints compact JSON and starts no work. `request_path` points to
the immutable full request, and `focused_regression_count` reports the number of
explicit selectors (zero for an unfocused check); the selector list is not repeated.
Exit status is 0 for `passed`, 2 for `running`, and 1 for `failed` or `incomplete`.
Running means the worker or an inherited child still holds the session lock. A missing final result after all
holders exit means incomplete, including worker interruption; a recorded PID
never decides status. The existing Cargo lane lock remains inherited throughout
native work. No status command kills, restarts or resumes a process. Inspect the
log before explicitly starting a fresh session after failure or interruption.
These records are mutable-source diagnostics; `prepare` does not accept or reuse
them as immutable release qualification.

For an exact optional regression diagnostic, use the same warm development lane:

    python3 scripts/taira_release.py check \
      --focus-regression core=sumeragi::node::tests::idle_chain_never_advances_and_real_work_survives_restart

Repeat `--focus-regression HARNESS=EXACT_TEST` for more selected regressions. Requested
`mv`, `mv-ebr`, `mv-map`, `mv-admitted-map` and `concread` tests compile and run
first, before configuration or the larger Core/CLI graphs. The runner finishes
and releases those copied executables before compiling configuration and the
remaining requested harnesses. Mandatory configuration checks gate that second
phase and remain required even for a portable-only diagnostic. Names must already belong
to the chosen `--native-check-scope`; unknown or repeated selections fail before
Cargo starts. Independent failures are aggregated; dependent network tests run
only after those checks pass. This mutable-source diagnostic writes no release
qualification checkpoint. Each phase reports its own Cargo feature graph; an
early pass does not qualify the later graph. `prepare` runs no regression checks
and accepts neither `--focus-regression` nor `--native-check-scope` nor a
`--build-only` switch. Omit the focus option to run the normal development
diagnostic. Reuse the same warm target across both phases; earlier failure
feedback does not imply a shorter total build when Cargo feature sets differ.

The CLI regression selection runs as one serial native test process, using exact
test names. This reuses immutable genesis fixtures instead of rebuilding them in
a new process for every test. The gate requires every selected result exactly
once and reconciles the complete result count with the process outcome; ignored,
missing, unexpected or malformed results fail qualification. A failed or aborted
batch reports unsuccessful and unexecuted tests without replaying successful
ones. Long batches emit progress updates. Configuration and mandatory startup
checks still run first, and node compilation and network fixtures remain later
steps. Both focused diagnostics and the complete gate use this CLI execution
path; other native harnesses retain their existing isolation.

Network observation tests run before shipping binary compilation. Selecting only
these tests requires no node binaries, four-validator workspace, or eight-GiB
runtime storage reserve. A failed observation stops before shipping compilation.
Selecting the beacon workload checks its private external workspace before
source audits or compilation: the directory must be owner-only mode 0700, outside
Git, with direct directory ancestors that reject group and world writes. Runtime
network tests also require eight GiB free before compilation and recheck capacity
before starting peers. The beacon workspace is revalidated at execution.

Prepare binaries from an explicitly selected signed commit in the optimizations repository:

    python3 scripts/taira_release.py prepare \
      --expected-commit FULL_SIGNED_COMMIT \
      --expected-signer REVIEWED_SIGNING_KEY_FINGERPRINT \
      --output-dir /absolute/private/output-for-this-build \
      --zig /absolute/real/zig \
      --zig-sha256 REVIEWED_ZIG_SHA256 \
      --cargo-zigbuild /absolute/real/cargo-zigbuild \
      --cargo-zigbuild-sha256 REVIEWED_CARGO_ZIGBUILD_SHA256

Every fresh preparation records `native_check_scope: "build-only"` and
`checks.passed: false`, meaning regression checks were not run. Signed source
capture, package closure, pinned tools, six jobs, release profile and immutable
artifact custody remain required. Existing failed or diagnostic records are never
relabeled as a successful check. Transfer and the same-revision owner-signed
dispatcher transition preserve the actual typed check evidence without requiring
regression success. Native deployment preflight, authenticated bootstrap,
finality and readiness still run; diagnostic canaries and restart proofs are
optional. The build result keeps `release_qualified` and `deployed` false.

Use independently reviewed tool digests and the full signing-key fingerprint
(GPG uppercase hexadecimal, or SSH SHA256 form). A valid signature from another
locally known key is rejected. Paths must be absolute and contain no
symlinks; PATH must resolve cargo-zigbuild to the supplied executable. Source
verification binds the maintained helper scripts to the supplied signed commit.
Git replacement refs are disabled. Every `BUILD_SOURCES` controller file is checked
against its signed Git blob and executable mode, independently of the mutable
index and flags that conceal local edits. Imported controller modules must come
from those checked paths; additional checkout modules cannot enter the controller.
Unrelated staged, unstaged and untracked work stays untouched and is never copied
into the build. Gitlinks retain their signed mode and commit in the capture and
remain empty there; worktree submodule contents are excluded. There are no
embedded tool digests or release-number-specific paths to update.

Fresh preparation and resume use the same source admission: the selected repository
must be on `optimizations`, and `--expected-commit` must name the exact signed Git
commit with the supplied full signer fingerprint and matching controller sources.
The selected commit can differ from HEAD, so unrelated commits already made on
`optimizations` do not enter a new build. The command does not move HEAD, modify
the index, or require another checkout.
It reads the selected commit's Git objects into a private, read-only source
capture under the selected Cargo target's `taira-release-sources/`. It creates no Git repository,
worktree or branch. The Linux build consumes this capture;
One explicit `source/target` binding points to the selected existing warm Cargo
target for native fixture output; source inventories verify this binding without
traversing generated files. Native fixture processes also run from that external
target directory. The snapshot covers signed Git entries; the output binding is
recorded separately as `source_output_target`. Every signed source path remains
read-only. Subsequent checkout edits, merges or HEAD changes cannot mix source
versions into the build. Resume additionally authenticates
the recorded request and captured bytes. Unrelated HEAD advancement is allowed
before fresh preparation and resume; a different branch, signer, or executing
controller is rejected before source capture. Changes to controller files require
a preparation selecting the signed commit containing those exact controller files.

Each selected warm Cargo lane has one stable source path. A lane-wide lock covers
capture refresh, Linux compilation and artifact capture, including
an active child if its launcher exits. Source replacement occurs only between
preparations. Unchanged files and complete unchanged directory subtrees retain their timestamps.
Directory watches in native build scripts therefore remain fresh when only
unrelated source changes. Added, removed, renamed, mode-changed, or edited
descendants invalidate their ancestors. Routine releases can
reuse Cargo's cache. Interrupted source publication is recoverable; previous
source directories and unfinished copies remain retained alongside the current
capture.

Cargo can retain dependency records pointing at an older source directory even
when the selected manifest changes. Before compiling, preparation inspects local
package records under Cargo's profile locks. Native checks inspect only the
debug profile family; Linux release builds inspect only the release profile
family, including their host build-script records. One family's admission never
retires the other's reusable fingerprints. Records for another source tree are
retained under `taira-release-cache-retired/`, outside Cargo's active fingerprint
lookup. Compiled outputs and registry/Git caches remain in place. Current-source
records are reused. After building, the same admission must pass without repairs;
Cargo's profile locks remain held through artifact capture. The regression suite
reproduces the stale host build script with two real source directories and proves
the corrected build executes the new source.

`check` defaults to the existing sibling `.taira-testnet-build-targets/routine`
development lane. Set `TAIRA_TESTNET_CARGO_TARGET_DIR` or `--target-dir` to select
another established development lane; when both are set, they must agree.
`prepare` defaults to the checkout's existing `target/` release lane and ignores
the development-only environment override. Its `--target-dir` must select an
established release lane. The commands enforce separate lane ownership: mutable
development checks cannot use a captured release lane, and authenticated
preparation cannot use the routine development lane. Preparation uses the
unchanged release profile and six jobs for exactly iroha3d_taira, iroha,
sorafs-node and kagami. Preparation selects the Rust toolchain from the captured
`rust-toolchain.toml`, then runs Cargo from `/` with the captured manifest and
`.cargo/config.toml` explicitly selected. A persistent config-free Cargo home
under the project target reuses the existing registry and Git caches. Ancestor
and home Cargo configuration cannot override these inputs; a root-level Cargo
config stops preparation with an actionable error. The captured Zig driver and
installed sccache remain in use. No target or cache is cleaned or replaced.
Compiler overrides, interpreter hooks and runtime credentials are not forwarded.
Optional `check` diagnostics use their selected toolchain and explicit target
directory. Both diagnostic scopes also verify that idle governance sweeps create no execution fragment,
while successful and failed due sweeps retain their effects and audit records.

Both scopes first verify that fresh catalog fixtures authenticate their intended
geometry during construction and retain their explicit network identity. A later
runtime update cannot replace the original storage catalog.

Both optional diagnostic scopes include certified catalog and bootstrap parameter
commit and recovery tests, plus rejection of changed parameters or mismatched
runtime effects after staging. The four-validator catalog test separately proves
the committed topology and transaction history survive restart and full replay.

Both scopes also require the generated validator configuration projection and
occupied-runtime recovery tests. The predecessor requires exactly five ordered
runtime roles: `iroha3d`, `config`, `genesis`, `genesis_hash`, and `validator_unit`.
Each has an explicit source revision, path, digest, size and mode. CLI, Kagami and
SoraFS are not predecessor validator dependencies; an eight-role predecessor
record is rejected. The configuration selector and exact process argv are bound
separately. An initialized installation may therefore retain artifacts from
different releases without treating its configuration revision as its executable
revision. Candidate artifacts still use one canonical release directory.

During optional diagnostics, after verifying the complete native Cargo output
set, a bounded owner-private
ledger records only final test executables and retires recorded superseded outputs
before checking copy capacity. Retirement runs under Cargo's locks after exact
inode checks and an OS open-file check; a later copy failure leaves the current
verified Cargo outputs intact.
The first run only records current outputs; unrecorded files, production binaries,
libraries, object files and warm compiler caches are retained. Busy files and
inconclusive or failed runtime `lsof` checks cause retention. A private quarantine closes
the old pathname before the final open-file check; interrupted retirement remains
recorded. Retries recover both rename windows using the recorded inode and stable
metadata, recheck open-file status, and never adopt an unrelated replacement. A
full ledger retries pending cleanup before admitting successors, so closing an
old reader restores progress without manual ledger edits.

Temporary executable copies, including non-CLI native network binaries, are
released after their last child exits, on success or failure. The published native
`iroha` CLI snapshot remains available to operator custody and deployment consumers;
the `cli` test harness is temporary. Exact identity and closed-file checks preserve
replaced or busy copies. If isolation fails partway through a batch, only already
verified copies are cleanup-owned, including an unpublished CLI; incomplete or
unrecorded files are retained. Observations and fixture logs remain. Cargo producers
and Linux release artifacts are outside temporary-copy cleanup.

Before publication, the shared artifact reader rechecks the pinned source bytes
against their captured SHA256 using bounded reads that preserve the stream offset.
This catches same-size edits even when filesystem timestamps coincide. Existing
metadata, path, copied-content and archive-content checks remain mandatory.

The standalone `check` command owns the native harness census and network
fixtures described in [Taira CLI release checks](taira_release_check.md).
It reports actual selected test outcomes; its failures do not become deployment
admission gates. `prepare` reconciles the shipping binary table with the signed
Cargo manifests and builds exactly the four shipping binaries from the captured
source. It writes no pre-network or independent-regression checkpoint.

Rerun the exact same `prepare` command and output directory after interruption.
The command locks that owner-private preparation directory, checks that its
recorded inputs still match the fixed signed source capture and tools, and resumes locally:

- A failed or interrupted build runs Cargo again in the same warm target. Cargo
  reuses its cache; each attempt gets a fresh private log and capture directory.
- A completed read-only capture is revalidated and reused without running checks
  or Cargo, including a crash before the final result was published.
- Changed input identity or a modified captured binary stops with a specific
  error. Active preparations retain their lock; a second command stops promptly.

The command reports stage durations and emits elapsed time, compiler-output size,
and the log path every 30 seconds during Linux compilation. It does not repeatedly
hash source or artifacts while reporting progress and does not impose an arbitrary
cold-build deadline. Captured source, tools and artifacts are checked at actual consumption
and reuse boundaries. Runtime secrets remain excluded from the child environment.

On a failed Linux build, the error includes the first bounded compiler or linker
diagnostic found in that completed log; the full output remains private.

Before initial source capture, local admission counts the signed Git blobs' exact
byte sizes without reading unrelated worktree files.
The signed-source transport exporter independently verifies its emitted pack,
complete object inventory, signature and symlink layout in a disposable Git object
database; it does not expand another working tree. Both export and import check
additional disk bytes and inodes before pack/source writes, including simultaneous
pack copies, native indexes and explicit control-file headroom. Native command
input scratch uses the actual Python temporary directory; isolated public signature
keyrings use the short `/tmp` path. Those locations are checked before scratch
creation, with 64 MiB of working headroom per allocation, and grouped by filesystem
alongside the output requirements. Import additionally
admits the expanded source files and verifies the full clean working tree before
exclusive publication. Capacity observations reserve no space and delete no caches.

An existing native client builder can admit a signed Rust successor without
replacing its original checkout, index, Git controls or warm target. Use
`scripts/taira_source_capture.py append` with independently pinned original and
successor capture manifests, their full commit/tree/signing fingerprints, the
successor pack and a fresh 32-digit operation ID. The successor's raw signed
commit must name exactly the previously admitted commit as its sole parent;
shallow Git traversal is not used. The selected build Bootstrap blobs must match
the live controller exactly, including trailing newlines. Existing Cargo and
source leases refuse overlap with a maintained native build.

The first append binds the exact original checkout and pack. Later appends
require `--prior-receipt` and `--expected-prior-receipt-sha256`. A durable intent
records the original custody and newly allocated pack/receipt inodes before
any live object publication. An interrupted operation must resume with the same
ID and independently retained `--expected-intent-sha256`; another operation,
unknown partial state or a same-byte foreign inode is refused. Receipts are
immutable. `verify-store` requires the current receipt SHA and selected signed
commit/tree/fingerprint, and reauthenticates the exact object union. The original
fresh-import receipt remains historical evidence; its strict single-pack
`verify` contract is unchanged. The store admits at most 32 complete direct
captures, 200,000 distinct objects, 8 GiB of logical object bytes and 4 GiB of
physical packs. Capacity checks include the new pack/indexes, overlapping
intent/receipt evidence and actual signature scratch filesystems; no successor
working tree is expanded by append. The ordinary `prepare-client` then captures
the selected signed tree into its existing source lane and keeps its full
controller process-origin checks. Append never compiles, fetches, checks out,
garbage-collects, activates a network or moves runtime secrets.

Before compilation, it groups requirements by filesystem and checks an 8 GiB
Cargo working-space floor plus 256 MiB capture headroom. Before capture,
it checks the exact binary-copy bytes plus that headroom. The build floor is an
operational minimum, not a prediction of Cargo's peak use. This local check cannot
observe a remote guest's sparse backing disk. Run the deployment capacity check
below on the guest and its backing host. No cache or output is deleted
automatically, and the warm Cargo target is never replaced with a new lane.

The output directory contains read-only `request.json`, `checks.json` with
`passed: false`, and `result.json`, a persistent private
`session.lock`, and numbered `attempts/`
directories. Failed attempt logs and partial captures stay available. Successful
captures contain four 0500 executables and a 0400 `capture.json`; its artifact paths
are returned in `result.json`. The successful attempt, capture and top-level output
directories are 0500. The mutable Cargo binaries remain in place. Existing unrelated
output directories cannot be adopted as resumable preparations.

This result remains a local build observation with `release_qualified=false` and
`deployed=false`. It is not an authenticated prebuilt-provenance manifest accepted
by `run_release_pipeline.py`, and local resume does not resume a deployment journal.

Canonical release signing remains in run_release_pipeline.py. Controller import
and native public-reset source-manifest, assemble, authorize, preflight and apply
remain separate operations under their existing authority. This helper accepts
no runtime keys, tokens, SSH, import, activation or publication options.

Validate the local orchestration without Cargo or network:

    PYTHONPATH=scripts python3 -B -m unittest discover -s pytests/scripts -p 'test_taira_release*.py'

Optional standalone selections and diagnostics are documented in
[Taira CLI release checks](taira_release_check.md).

## Transferring a prepared release

Use [the maintained transfer command](taira_release_transfer.md) to import a
completed preparation's four binaries and exact signed source into the approved
MacStadium guest. It validates the preparation and checks both physical backing
and guest capacity before payload writes. Completed transfers are revalidated on
retry; an SSH or storage failure does not require rebuilding unchanged artifacts.
The command publishes verified binary/source receipts and leaves activation to
the native deployment workflow below.

## Preparing validator configuration for a public reset

Generate the fresh four-validator Taira bundle with the same-revision native Kagami
on the approved Linux validator host. Keep its private output outside Git at the
same absolute path throughout installation and operation. Project each generated
validator through the same-revision native CLI using an inherited owner-private
descriptor:

    iroha taira public-reset materialize-validator-config \
      --config-fd 198 \
      --localnet-dir /absolute/private/generated-network \
      --validator taira-validator-1 \
      --network-id REVIEWED_CHECKED_NETWORK_ID \
      --genesis-file /srv/taira/taira-validator-1/releases/COMMIT/genesis/genesis.json \
      --operator-public-key REVIEWED_CANONICAL_OPERATOR_PUBLIC_KEY \
      --torii-bind-address 0.0.0.0:8080 \
      --trusted-proxy-ip 192.168.64.1 \
      --output /absolute/private/taira-validator-1.toml

Descriptor 198 must already identify the corresponding generated peer config;
the command does not open a private input by pathname. It verifies the generated
public genesis identity, maps all eleven mutable paths into the validator's
reset-managed state directories, sets explicit snapshot storage, and binds the
installed signed genesis and operator-authentication key. It rejects inherited
configuration, changed source paths and preexisting output. It emits no private
configuration to stdout. The required `--torii-bind-address` selects a canonical
IP and nonzero port; the port must equal the generated Torii port. For the
MacStadium deployment, generate with `--bind-host 127.0.0.1` and project Torii to
`0.0.0.0:8080` through `0.0.0.0:8083` for the four corresponding validators.
Pass the approved Mac-to-guest proxy address explicitly with
`--trusted-proxy-ip 192.168.64.1` for this deployment: MCP and per-validator
routes connect directly from that hop, while the shared guest edge uses
loopback. Other deployments must supply their own observed proxy host address.
The repeatable option accepts individual canonical unicast IPs, installs exact
`/32` or `/128` trust entries alongside loopback, and grants no rate-limit bypass.
The proxy must supply the socket-observed client address in `X-Forwarded-For`.
P2P listeners and advertised peer addresses remain unchanged. The generated
onboarding key, faucet key, public rANS
table and `nexus.registry.manifest_directory` paths remain in the configuration,
so their original directory must remain available on that host. The manifest
directory must be exactly `lane-manifests` under the generator directory; a
registry cache overlay is rejected. Native signing and startup bind its semantic
policy digest to signed genesis. Retain and revalidate the generated public
manifest receipt for exact byte custody; the reset inventory does not declare a
separate manifest artifact.

Assembly, authorization and forward preflight require every candidate faucet to
be enabled, with authority, canonical asset and quantity exactly matching the
independently signed intent. This policy check reads the pinned configuration
without opening faucet signer files.

Derive the complete public identity bundle using the maintained CLI:

    iroha taira public-reset prepare-public-inputs \
      --localnet-dir /absolute/private/generated-network \
      --intent /absolute/private/topology-intent.json \
      --output-dir /absolute/private/public-inputs

The closed `iroha.taira.public-reset.topology-intent.v1` contains topology, paths
and explicit authority only. Computed release/config/artifact pins and generated
beacon plans are not fields. Native validation extracts the
canary public identity from its exact onboarding request and validates the signed
genesis against the generated raw manifest. The command atomically writes six
public artifacts: `genesis.json`, `genesis.signed.nrt`, `genesis.hash`,
`nexus-amx-context.v1.bin`, `canary-onboarding-request.json` and
`public-inputs.json`, with mode0644 inside a mode0700 directory. The typed record
binds `raw_manifest_sha256` and `nexus_amx_context_sha256` and distinguishes
the native consensus genesis hash from the signed wire's SHA256. The exact context
preimage must hash to the signed genesis commitment and pass the current typed
decoder; the generator emits it alongside signed genesis. An incomplete six-file
bundle is rejected; prepare a fresh complete output. Repeating an
identical complete request verifies the retained bundle without replacing it.
The explicit `--canary-public-key PATH` alternative is mutually exclusive with
`--intent` and reads only that public key.

Derive the fresh beacon request and exact per-validator credential paths from the
same topology intent and public bundle:

    iroha taira public-reset prepare-beacon-inputs \
      --intent /absolute/private/topology-intent.json \
      --public-inputs /absolute/private/public-inputs \
      --output /absolute/private/beacon-inputs.json

Use the authenticated same-revision unit renderer for each returned final-unit
entry, preserving its initial runtime-key path and using
the exact native `credential_path` with `--global-beacon-credential` and
`--config-file beacon.toml`. The [maintained retry caller](taira_retry.md) verifies
the pinned renderer and initial units before rendering these four final mode0644
units. The native request is not hand-authored JSON.

`public-reset assemble --intent PATH` and `authorize` require the same
`--public-inputs DIR`, `--beacon-inputs PATH`, four ordered
`--beacon-validator-unit` paths, runtime client, four validator client configs,
operator key, onboarding token, initial validator units, native edge capability,
and known hosts. Full scope also requires its Inrou stage. Native assembly independently
rederives the source, credential joins, signed genesis, beacon request, and seat
map before signing. Apply receives only admitted runtime inputs.

The same-release artifact closure includes Kagami. Reset installs no epoch
maintenance worker; old worker state or service files reject host preflight.
The production epoch boundary applies the authenticated validator epoch graph
and its certified activation or retention decision.
See the [maintained retry caller](taira_retry.md) for the current path records
and preparation order.

The signed genesis must leave room for onboarding, funding, the canary's real
Ordinary transactions, real DKG completion, and the
certificate installation before the first mandatory beacon pulse. Finalization
uses the authenticated observed height. The sole threshold-key certificate uses
signed Ordinary admission with exact next-height and current-roster quorum
checks. Supported public prepared transactions use signed Ordinary single-route
admission; unsupported multi-route intents fail before durable acceptance.
The certificate must be committed on all four validators, followed by all four
`BeaconActivate` provider installations before restart proof. Epoch retention
observes complete authenticated Retain transitions on finalized workload
blocks; it never creates empty blocks.

Public validator client settings can reference the native-generated
`runtime/taira-runtime-signers/peerN.private_key` sidecar through
`account.private_key_file`. Use the exact checked `network_id_file`, account
`chain_discriminant = 369`, and each validator's Torii origin. Extract the
canonical public key from its generated public manifest account with the native
`iroha tools address convert ACCOUNT --profile taira --format public-key`.
This representation requires a single-signatory account and rejects multisig
controllers. No private configuration parsing is needed to construct these
public fields and file references; native loading validates the key pair.

Each candidate validator includes eight exact artifact roles, including same-release
Kagami and the `validator_unit` artifact at
`systemd/<systemd_unit>` with exact mode 0644. Assembly requires its bytes to
match the explicit validator unit input and digest. Reset execution durably
retains the prior unit, records publication intent, atomically installs the
candidate unit and records the exact service-manager reload. Interrupted forward
and rollback publication resume only from that durable evidence. An occupied
validator additionally signs its required prior `service_state`: `running`, or
`stopped` with the independently selected state-root device/inode. There is no
implicit state or fallback from a failed running-process check. Both modes retain
all exact prior artifact, loaded-unit, selector and custody checks. Stopped mode
also proves no service job, PID, populated cgroup or escaped state reference.

Reset retains the original state inode at
`<reset_guard>/rollback/<authorization_nonce>/state` by same-filesystem rename;
it does not copy old ledger contents into the newly initialized chain or create
an off-host backup. Approval must identify the old/new genesis and resulting
active-state loss. Rollback before deployment proof restores the old unit,
selector and retained state. Running mode proves the restored old process;
stopped mode stays stopped and proves absence, without claiming recovery or
health. Cached and conservative rollback use the same signed state. Cleanup
protects the selected prior configuration release and every admitted runtime
artifact root using authenticated occupied-target records. Malformed or
inconsistent prior state cannot authorize cleanup. Proven deployments cannot roll backthrough this workflow, and ambiguous writes require their retained recovery path.

These preparation operations do not authorize replacement of shared network
state. The reviewed inventory, explicit reset authorization, and independently
provisioned trusted host dispatcher and reset guard remain prerequisites for
`public-reset apply`. The candidate cannot provision its own host authority.

For an explicitly authorized fresh reset after deployment proof whose seal
bookkeeping remains unfinished, select
`public-reset prepare-dispatcher-transition --deployment-proven-predecessor`.
This admits the genuine immutable `deployment-proven` receipt together with the
exact unresolved operational journal, sealed guest progress with no pending
action, the expired predecessor lease, the stopped current runtime and the
independently signed native edge capture. The journal must agree with the proof
except for its bounded seal-failure diagnostic. Both original files remain
unchanged; this does not claim that the old deployment completed. The new
source, artifacts and reset authorization retain their normal custody and
signature checks. This selection conflicts with `--terminal-rolled-back`.

For first-time native custody, use the same-source Kagami key owner with two
separate fresh directories, one for native capture and one for the independently
selected release authority:

    "$NATIVE_DARWIN_KAGAMI" keys --algorithm ed25519 \
      --out-dir "$FRESH_NATIVE_CAPTURE_KEY_CUSTODY"
    "$NATIVE_DARWIN_KAGAMI" keys --algorithm ed25519 \
      --out-dir "$FRESH_RELEASE_OWNER_KEY_CUSTODY"

Each invocation atomically publishes `public.key` and `private.key` as mode0600
files in a new mode0700 directory; stdout reports file paths without key secrets.
Existing destinations are refused. Keep the capture key separate from release
authority: its public key belongs in the signed native host pair, while the
release owner's public key belongs in the independently approved `TrustedKeyV1`
record. Generating a pair does not approve that authority. Native authorizers
consume each `private.key` only through its inherited signing descriptor
(`--native-signing-key-fd` or `--owner-signing-key-fd`); controllers and public
records use public keys, paths and metadata. Follow the
[native capture and owner authorization runbook](../../crates/iroha_cli/DISPATCHER_TRANSITION.md)
for the exact descriptor and public-input contracts.

The explicit OS-operator bootstrap command is
`iroha taira public-reset initialize-native-edge-custody
--expected-executable-sha256 SHA256 --trusted-public-key PUBLIC_TRUSTED_KEY_JSON
--expected-trusted-public-key-sha256 SHA256`. It uses the actual named Mac
account's home and currently invoked native image, requires release source
identity, and publishes the fixed dispatcher, guard and exact public authority
record under `.local/share/iroha/taira/public-reset-v1` as one fresh private
directory. Both digests must be selected independently. Matching dispatcher,
guard and public-key anchors return a read-only receipt after normal use;
operational children remain untouched and receive no authority from this check.
Missing, indirect or different anchors and incomplete roots are refused. This
command takes no private key and changes no services. Its
`qualified=false` receipt establishes bootstrap custody, not deployment proof;
signed source and release admission remain required. The implementation is
`crates/iroha_cli/src/taira_public_reset_native_custody.rs`.

## Updating an initialized testnet

`scripts/taira_update.py` updates an existing four-validator deployment from a
completed maintained artifact preparation. Its deployment record binds the
approved SSH routes and host-key pins, network, retained directories and
completed predecessor receipts. Keep that record outside Git and use one
explicit fresh `update-<32hex>` operation for artifact preparation and apply.
The update preserves validator signing custody. Scheduling epochs retain the
incumbent authenticated authority; no separate key-renewal worker is required.

Prepare the exact same-release daemon, CLI and Kagami at the operation's immutable
release path:

    python3 scripts/taira_update.py \
      --prepare-artifacts \
      --deployment /absolute/owner-private/taira/deployment.json \
      --prepared-result /absolute/completed-preparation/result.json \
      --operation update-0123456789abcdef0123456789abcdef \
      --output /absolute/owner-private/taira/artifact-output

Review the deployment plan with `--plan-only`, then apply using the same
operation and a fresh output path:

    python3 scripts/taira_update.py \
      --deployment /absolute/owner-private/taira/deployment.json \
      --prepared-result /absolute/completed-preparation/result.json \
      --operation update-0123456789abcdef0123456789abcdef \
      --output /absolute/owner-private/taira/update-output

`--plan-only` writes the concrete plan locally without contacting the host.
Artifact preparation creates the exact same-release daemon, CLI and Kagami
without overwriting existing files. Apply requires all three prepared binaries
and rechecks their native digests, sizes, source and root-owned mode0755
custody. It never creates missing binaries or invokes Cargo. Configuration,
validator credentials and ledger state remain under their native owners. The
updater submits no transactions and accepts no retired worker plan fields.
During guest apply, it reports the phase, elapsed time and owner-private attempt
path to stderr at start and every 30 seconds. A failed or timed-out child reports
that path without printing captured stderr; submission has one bounded timeout.

Artifact transfer, admission and apply share the existing root-owned, mode0600,
empty, single-link `/var/lib/taira-deployment/.deployment.lock` with reset and
retry. The containing directory has root ownership and mode0700; a missing lock
is an error. While holding it, the updater rejects a retained
`.reset-owner.json`, any `/var/lib/taira-epoch-supervisor` path, and any
`/etc/systemd/system/iroha-taira-epoch-supervisor.service` path, including
dangling links. It does not decode or run the retired worker. Retained reset
ownership and obsolete worker state require operator reconciliation.

All four validators must prove the candidate identity and restore their own
stopped retained tips. Every overlapping stopped prefix is checked before
startup. Two fresh samples must each contain at least three Ready validators
agreeing on the stopped cohort's highest committed block hash. Each sample
attempts all four validators and records missing, unready and lagging peers;
stale observations never contribute to quorum. After the public health check,
the updater repeats both quorum samples and checks all four unchanged
processes. Identity, hash, malformed response and process failures stop
immediately; only declared startup transport failures and HTTP 503 are polled.
An idle chain need not create another block. An ambiguous stop admits read-only
reconciliation. A pre-start failure leaves the previous cohort stopped; after
candidate startup, failure contains that cohort without reverting execution
rules, even if failure-receipt publication fails.

After all four stopped checkpoints are recorded, the matching candidate CLI runs
`iroha taira stopped-owner-maintenance` once before unit replacement or startup.
It verifies the live updater parent and its update flock, the retained public plan,
the exact stopped units and state roots, and acquires all four existing signer
slot locks before cleaning stopped native owners. Python passes only public
operation and process identities through a read-only descriptor; the native
custody boundary owns cleanup. The operation retains a maintenance intent,
per-slot receipts and `stopped-owner-maintenance-result.json`. Native maintenance
has a 120-second deadline and its caller a 150-second timeout. Failure leaves
the cohort stopped for inspection and prevents candidate installation or startup.

Local and guest locks serialize updates. Each operation retains its own staging
and evidence paths, so a failed transfer or lock conflict can use the same
completed binaries in a fresh operation after inspection. Failed stages remain
on disk. An interrupted runtime mutation requires recovery before another update;
there is no automatic rollback to earlier execution rules after candidate start.
A successful update emits `next-deployment.json` for the next invocation. Confirm
an application transaction as state-resolved Applied after installation.

For an update that installed all four units and failed after starting the new
daemon, retain the last completed deployment record and pass
`--failed-start-chain /absolute/owner-private/taira/failed-chain.json`.
Use schema `taira.failed-start-chain.v1` with an `attempts` array ordered oldest
to newest. Each entry contains its exact `operation`, a `plan` reference, and
`records` references for `intent.json`, `before.json`, `checkpoint-stopped.json`,
`start-intent.json`, and `failure.json`. Every reference contains the absolute
public-record `path` and its `sha256`; `plan` and `intent.json` bind identical
bytes. Capture only these public records. When appending a failed corrective
attempt, preserve all earlier entries and historical records unchanged.

The chain admits 1–16 distinct operations, with an 8 MiB bound per public record
and a 32 MiB aggregate read budget. Each intent must authenticate the exact earlier
prefix. Installed unit bytes follow the immediately preceding attempt; accepted
health remains the unchanged completed baseline. Every ancestor must have all
four units installed and a recorded startup failure, with no completion or
rollback marker. The guest checks every retained Kura prefix before its normal
stop/checkpoint/start verification. Partial observations remain diagnostic.

Retry the same retained `--prepared-result` after an infrastructure failure; a
new operation does not require Cargo or a source change. Any reused source commit
must retain the exact daemon and CLI package, size, and digest throughout the
chain. A rebuilt binary with a different identity under that commit is rejected.
Every retry uses fresh staging and evidence, preserves the latest authenticated
snapshot and Kura prefix, and repeats all four-validator health checks. It never
promotes a failed attempt to completed health or automatically restarts old code.

Probe failures identify the validator, endpoint and native exit code. Process
observations include PID, invocation and restart count so an unavailable listener
can be distinguished from a restarted worker without exposing response bodies,
configuration or native error output.
Startup and unhealthy observations have a ten-minute limit. Each lagging peer
gets another ten minutes only when healthy observations of the same candidate
processes show that peer's committed height advancing. Another peer's progress
cannot conceal a stalled validator, and a height regression is rejected.
Catch-up has an absolute ninety-minute limit; the host adds a conservative
bounded allowance for staging, final checks and all sixteen possible ancestry
records. The updater returns as soon as
all four peers verify the existing common prefix and readiness. Waiting never
restarts a daemon, rebuilds a binary, requires empty blocks, or adds a fixed soak.

After native start succeeds, `cohort-observation-intent.json` identifies the
read-only observation phase by operation, candidate, updater PID/start time and
the existing update flock's device/inode. A separate observer can verify that
live owner through public procfs and check that no terminal receipt exists.
This records an in-progress rollout; it does not assert four-peer completion.

Validate this controller without Cargo or network:

    python3 -B scripts/tests/taira_update_test.py

## Deployment capacity and retrying an unchanged release

Keep the build identity separate from the deployment attempt. A storage or host
failure does not require another build, source import, or binary transfer when
the retained artifacts still match their successful preparation and transfer
receipts. After a completed native rollback, retain its terminal record and
create fresh deployment custody and authorization for the same artifacts. Never
replay the failed authorization or edit a terminal journal to resume it.

Use the maintained retry command with the retained preparation, transfer and
runtime evidence:

    python3 scripts/taira_retry.py \
      --plan /private/runtime/taira-retry/operator-plan.json \
      --output-root /private/runtime/taira-retry/local-evidence

It allocates a new attempt automatically, preserves completed rollback history,
runs native assembly and authorization, and completes seed continuity and boot
persistence. Repeating it before apply resumes the same operation; after the
durable apply frontier, a real native rollback terminal is required. See
[the retry command](taira_retry.md) for input custody, capacity admission and
public application validation. No numbered retry adapter needs to be edited.

Before preparing a deployment, and again immediately before apply, run:

    python3 scripts/taira_disk_capacity.py --plan /absolute/public-capacity-plan.json

The public JSON plan uses schema `taira.disk-capacity.plan.v1` and an
`allocations` list. Each allocation has exactly `path`, `label`, `bytes`, and
`inodes`. Quantities describe additional allocated space, including concurrently
live temporary files and explicit operating headroom. The helper resolves paths
without following symlinks, groups requirements by actual filesystem, and checks
both available bytes and inodes. It reads no configuration or credentials and
performs no cleanup. Failure returns exit code 2 with required and available
quantities. Success is an observation, not a disk reservation.

For the current four-validator deployment on one physical guest, a fresh attempt
requires `3*A + 2*S + 4*P + 4*R`, plus operating headroom:

- `A` includes the complete artifact sets for all four validators and the edge.
  The coordinator snapshot, host uploads, and installed releases coexist.
- `S` includes the full Inrou stage tree. Its coordinator snapshot and host upload
  coexist with the already retained source tree.
- `P` includes one complete SoraFS store: all three payloads, chunk allocation
  slack, manifest and PoR metadata, index files, and temporary publication files.
- `R` includes one replica's hydrated guest, independent writable root disk,
  application extraction and publication, data lease, ephemeral storage, and
  runtime metadata. All four replicas keep their own runtime files.

The helper's `allocation_bound` and `cohost_peak_plan` functions construct these
byte and inode bounds. See [the allocation contract](taira_disk_capacity.md) for
the persisted metadata limits and backing-volume requirements. Logical SoraFS quotas are not free-space checks. Existing
files are already charged against available space; do not subtract proposed
cleanup until it has actually completed. Check a sparse VM's physical backing
filesystem separately, including its possible additional allocation.

When reclaiming failed attempts, remove only identified obsolete generated
payloads that have no live references and are outside current deployment or
recovery inputs. Hold the deployment coordinator and physical-host action locks.
Retain terminal journals, manifests, cleanup receipts, runtime custody, and the
current artifact set. Repeatedly retaining every large failed upload eventually
exhausts the guest even when the next store fits its logical quota.

Validate the capacity helper without network access:

    python3 -B -m unittest discover -s scripts/tests -p 'taira_disk_capacity_test.py'
