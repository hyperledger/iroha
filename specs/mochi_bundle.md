# MOCHI Bundle Tooling

MOCHI ships with a lightweight packaging workflow so developers can produce a
portable desktop bundle without wiring bespoke CI scripts. The `xtask`
subcommand handles compilation, layout, hashing, and (optionally) archive
creation in one shot.

## Generating a bundle

```bash
cargo xtask mochi-bundle
```

By default the command builds release binaries, assembles the bundle under
`target/mochi-bundle/`, and emits a `mochi-<os>-<arch>-release.tar.gz` archive
alongside `manifest.json` with a sorted file inventory. The manifest lists every
file with its size and SHA-256 hash so CI pipelines can re-run verification or publish
attestations. The helper builds `mochi`, `kagami`, and `iroha3d` together in one
locked Cargo invocation and includes all three native executables. A prior
binary's existence is not a freshness check. Arbitrary Kagami overrides are
not accepted by the bundler, so it cannot mix a supplied helper with a newly
built daemon.

### Flags

| Flag                | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| `--out <dir>`       | Override the output directory (defaults to `target/mochi-bundle`).         |
| `--profile <name>`  | Build with a specific Cargo profile (e.g., `debug` for previews); `local-release` cannot be packaged. |
| `--no-archive`      | Skip the `.tar.gz` archive, leaving only the prepared folder.               |
| `--matrix <path>`   | Append bundle metadata to a JSON matrix for CI provenance tracking.         |
| `--smoke`           | Check packaged help, config-free deployment/restart, three-provider package publication, and cold dependency execution on four validators. |
| `--network-profiles <path>` | Development profiles only: validate an explicit installation artifact. Release uses the committed preset described below. |
| `--stage <dir>`     | Copy the finished bundle (and archive, when present) into a staging folder. |

Release packaging requires `defaults/developer/network-profiles.nrt` from the authenticated
release source, containing the independently approved Taira release key, rollback floor and
checkpoint URL. The packager requires its exact committed image and refuses an override,
missing file or absent Taira entry before building or replacing a bundle. The preset is sourced
from the approved [Taira publication](https://taira.sora.org/bootstrap/network-profiles.nrt)
and selects `https://taira.sora.org/bootstrap/checkpoint.nrt`. Its SHA-256 is
`29a9d26dfb40293280bbfcde7b30f2d5f3f635c5e18bbc4e1a8878efd9acd18f`;
the release owner must commit those exact bytes. Checkpoints remain fetched artifacts with
bounded signed validity; recurring publication is an operator responsibility. The packager
generates no authority. Developers using an installed official bundle supply no file.
Debug/development bundles may omit profiles or use explicit fixture installation input.
The same xtask selection owner gates the CLI-only `kagami-bundle` release path, which
installs the identical original preset beside Kagami and the daemon and records its
public provenance in that bundle's manifest. Neither packager accepts a release override.

`--stage` copies the completed package into a fresh or already owner-private
staging root. Existing bundle or archive names and unsafe roots are refused before
copying. The original native artifacts, exact inventory, manifest, profiles and
archive stay retained through private staging and exclusive publication; final
copies are rechecked against that original authority. Archive copying and hashing
stream through a 32 GiB packaging bound. Directory and archive publish separately:
if archive publication fails after the directory completes, the command reports
both complete-directory and pending-archive paths for reconciliation and returns
an error. It never deletes an incumbent or reports a partial pair as success.
Use a fresh staging name for the next candidate; failed private copies may remain
for diagnosis. The shared Windows directory publication gate closes staged output
handles immediately before rename, then rechecks exact objects and hashes against
the retained original source package.

The canonical macOS package has one native application:

```text
Mochi.app/Contents/Info.plist
Mochi.app/Contents/MacOS/mochi
Mochi.app/Contents/MacOS/kagami
Mochi.app/Contents/MacOS/iroha3d
Mochi.app/Contents/Resources/network-profiles.nrt # required release-owned Taira preset
docs/README.md
LICENSE
manifest.json
```

`iroha_deploy::managed::NativeBundleLayout` owns package paths for assembly,
installed smoke and latency controllers. Linux/Windows use `bin` for programs
and profiles, with `.exe` on Windows. macOS ships no outer copies or launcher
scripts. The generated plist uses `org.hyperledger.iroha.mochi`, executable
`mochi`, and the explicit numeric version from the **mochi-ui package manifest**.
Assembly is not code signing or notarization; those remain separate release
qualification work.

Installed runtime discovery admits the host-native executable format and live file custody
of both Kagami and the daemon, retaining their original descriptors. Requests produced by that
runtime share the selection across clones. Startup revalidates the original files and bound request paths
before generation preparation, holding program owners through launch and readiness. These source
fences neither authenticate build provenance nor make pathname execution atomic.
Discovery accepts a direct `.app/Contents/MacOS` directory
and loads profiles only from that application's `Contents/Resources`. Moving or
renaming the application before first use preserves this relationship. Existing
managed generations retain their original pinned executable paths; package
relocation does not silently rebind them. Direct loose developer executables
(e.g. `target/debug`) are also supported explicitly and keep profiles beside
their programs. This development mode is not an alternate macOS package layout.

The manifest inventories all packaged files except itself, including the plist
and installed profiles. Inventory and staging propagate traversal failures and
reject symlinks or other nonregular entries instead of silently omitting them.
The inventory is sorted by relative path; its hashes need authenticated release
provenance before they establish download trust.

`--smoke` first checks the exact retained profile image and packaged Kagami network-name
projection. It then runs the packaged Kagami from an empty workspace with an empty `PATH`.
It supplies no TOML, starts the localnet through `contract deploy hello.ko`,
also deploys `.to` and a local Musubi package, and verifies artifact readback and
a live contract result on each of the four peers. It checks repeated starts and
deployments, then stops and restarts all four validators. The exact deployment
receipts and journals must survive. On the same generation, it publishes a library
through `kagami package publish`, resumes only that original operation within a
bounded deadline, and requires complete publication plus the exact three original
healthy providers and signed attestation set in every validator's native registry
view. It removes the fixture's source, then deploys a separate contract with an
exact registry dependency and checks the result on all four peers. The managed
build cache must be absent before this dependent build; publication uses its own
cache. Native resource limits remain unchanged. The same smoke then creates a second genuine named
context, with only one network running at a time. It checks context list/show/use, explicit
`contract deploy --context` without changing workspace selection, and original-journal recovery
after restarting the intended network. Both deployments are read and executed on all four
validators; cleanup covers both named environments.

After that workflow passes, separate fresh stores exercise `.to` and local-package
inputs as the first deployment command. Each must start four validators, execute
the contract on every peer and return the original receipt on repetition, without
supplied runtime configuration or build tools on `PATH`.

Stock managed Global localnets and private roots use an explicit SoraNet admission
cost profile only when every generated P2P/Torii listener, advertised peer and
telemetry endpoint is numeric loopback: Argon2id uses 4,096 KiB, one iteration,
one lane and difficulty 6. This deliberately lowers local denial-of-service work
cost; it is not the public deployment cost profile. The mandatory puzzle,
transport/transcript binding, replay protection and ticket lifetimes remain in
force. Exported localnets, public chain identities, hostnames and non-loopback
managed endpoints retain the standard admission defaults (65,536 KiB, two
iterations, one lane, difficulty 6). Consensus and signed genesis are unchanged.

Cleanup uses authenticated localnet control; failures retain the private runtime
directory and diagnostics. The combined installed publication regression has not
yet been executed for the current candidate. The matrix retains the exact profile SHA-256, source path/commit for release input, and
profile names, plus the archive SHA-256 when present. It records `local_native_diagnostic` and keeps official Taira attachment
qualification false. This single-run smoke does not
establish the twenty-run latency target or remote private-dataspace acceptance.

The smoke's source, bytecode and local-package contracts have distinct behavior
and must produce pairwise distinct artifact hashes. The test controller prepares
the `.to` fixture offline with the canonical compiler; installed commands still
run with an empty `PATH` and no external compiler.

### Diagnostic latency samples

The contributor-only collector uses an existing bundle, separate fresh managed
state for each of twenty attempts, and the same bounded installed CLI controller:

```sh
cargo xtask mochi-latency --bundle target/mochi-bundle/mochi-<os>-<arch>-release --out target/devex-latency
cargo xtask mochi-latency-report --samples target/devex-latency --out target/devex-latency-report.json
cargo xtask mochi-latency-remote --bundle target/mochi-bundle/mochi-<os>-<arch>-release --driver <matching-release-iroha_deploy-test-executable> --out target/devex-remote-latency
```

Startup and ready-environment `.ko`, distinct `.to`, and local Musubi package
deployment are separate cases. The timer includes foreground CLI startup and
receipt processing; exact artifact readback and views on all four peers are
required postconditions outside that duration. “Fresh” means empty managed state,
not a flushed OS page cache. Fixture compilation and hashing are outside the timer.
No case measures a cold remote-provider package fetch.

Samples contain fixed outcome codes, integer nanoseconds, execution OS/architecture
and observed bundle hashes before/after; private logs and journals stay in
temporary custody. Aggregation preserves the recorded execution host and rejects
mixed hosts. Failures remain in the attempted count, and missing cases remain
incomplete. No retry replaces a failed ordinal. P95 is the nineteenth ordered
observation only when all twenty attempts for that case and all twenty overall
runs succeeded. Failed or uncertain cleanup retains private diagnostics;
uncertain cleanup stops the campaign.

The remote entry point invokes the exact eight-validator installed regression
twenty times sequentially. It records attachment and the three distinct private
deployment inputs separately, all labeled as a disposable loopback parent with
TLS. Deployment timing ends at local CLI Applied; exact child scope, artifact and
all-peer views remain required postconditions. Later parent anchoring is separate
evidence. The test driver digest, whole-test exit and authenticated cleanup of
both native stores and the TLS controller are recorded independently. Any later
proof, privacy or cleanup failure prevents a successful campaign or p95 threshold
claim, even when an earlier command succeeded. Missing dependent cases remain
unattempted. A missing cleanup confirmation stops further ordinals.

The remote report is written at `<out>/report.json`; raw typed records are in
`<out>/samples/` and can be passed to `mochi-latency-report`. A matching normal
release test driver is an externally verified prerequisite, not established by
its filename or digest. Python/OpenSSL belong only to the disposable test
controller, and no product installation gains a Python requirement.

Every report is diagnostic. Collection rejects non-release bundle profiles, but a
manifest hash or `profile: release` label does not authenticate a build. Signed
exact-source release provenance and qualified reference hardware remain separate
requirements for local results. Remote qualification additionally needs a healthy
funded parent with measured RTT and independently published network trust; the
disposable loopback workload cannot qualify Taira. The collector cannot promote
caller assertions into qualification.

The collector is implemented in source; no twenty-run campaign has yet been
executed for the current candidate. This section documents its measurement
boundary, not a measured performance result.

The `cargo xtask` alias enables the required `dev-tools` feature. Native release
qualification is dispatched through `.github/workflows/devex_native.yml` using
five explicitly supplied existing runner labels. Its resource and host checks,
native custody tests and installed-runtime smoke are execution gates; defining
the workflow does not establish that those platform jobs passed. An installation
built with a development profile may omit remote authority. Release packaging requires
the committed Taira preset; a successful local smoke still does not qualify remote attachment.
The workflow also runs the eight-validator attachment regression with its
disposable TLS controller. Python 3.10+ with SSL and OpenSSL are test prerequisites;
the controller supplies a private temporary CA only to its own child processes.
Installed Kagami and Mochi flows continue to use the native bundle alone.

### Workspace selection

The packaged desktop selects the same workspace context as Kagami:

```
./Mochi.app/Contents/MacOS/mochi --workspace /path/to/project
```

Omitting `--workspace` selects the current directory. Generated configuration,
credentials and retained ledger state live in private OS application storage.
The desktop uses the matching sibling Kagami and daemon; it does not require
sample TOML, invoke Cargo, search PATH for a daemon or own a second supervisor.

## Snapshot automation

`manifest.json` records the generation timestamp, target triple, Cargo profile,
and the complete file inventory. Pipelines can diff the manifest to detect when
new artefacts appear, upload the JSON alongside release assets, or audit the
hashes before promoting a bundle to operators.

Each build publishes a complete bundle once from private staging. Existing bundle
or archive names are refused before building; select a fresh `--out` directory for
another candidate. Failed native admission or publication preserves prior outputs.
Original Cargo artifacts stay retained throughout publication. Windows requires
closing output handles before renaming the complete directory; final readers
recheck each exact captured native object snapshot, executable format, and hash.
Archive failure retains the new owner-private incomplete archive and the already
complete bundle for diagnosis, without reporting success. A later invocation refuses
these occupied names; select a fresh output directory.
