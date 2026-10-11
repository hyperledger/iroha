# CI Helpers

This directory hosts the developer-facing shell helpers that gate CI jobs
(`ci/check_*.sh`). Most scripts assume the default Cargo artifact layout under
`target/`, so keep that layout unchanged unless the entire toolchain is updated
as part of a coordinated migration.

## Affected Rust lanes

`ci/rust_lanes.toml` assigns every Cargo workspace package to exactly one
validation lane. `scripts/rust_ci.py` reads locked Cargo metadata, identifies
the package that owns each changed path, and expands that seed through the
workspace reverse-dependency graph. The PR workflow runs locked Clippy, build,
test, and documentation commands for the resulting package sets, then exposes
one required aggregate result.

Torii integration tests require its explicit `test-fixtures` feature. The routed
test command enables it whenever Torii is selected; a direct full Torii run uses
`cargo test -p iroha_torii --features test-fixtures`. Owning mutation checks use
`python3 scripts/sumeragi_mutation_gate.py --torii --strict --jobs 1`. Torii has
no self dev-dependency: that edge would compile the mutation feature into a
non-test library, which its shipping guard rejects. Unit fixtures use `cfg(test)`.

Package-level `package_binaries` requirements split each selected lane into
binary-free and network package sets. The first set starts immediately after
classification; only the second waits for release artifacts. The network
packages are `iroha_test_network`, `izanami`, and `integration_tests`, which
receive `iroha3d` and `iroha`. The first and third also receive
`iroha3d_private_settlement_routes` through `TEST_NETWORK_BIN_IROHAD_PRIVATE_SETTLEMENT_ROUTES`.
Its `irohad/test-network-private-settlement-route-control` feature is compiled separately under
`target/ci-binaries/private-settlement-route-control`; shipping artifacts use
`target/ci-binaries/shipping`. Staging preserves both distinct daemon files.
Cargo's `CARGO_BIN_EXE_*` supplies sibling binaries for other package tests.

Foundation-only source changes retain the affected library and local CLI
checks, while deferring node-launching packages and the manifest's
`daemon_packages` owners. This includes changes to `iroha_crypto` and `norito`:
their reverse dependencies remain visible in classification evidence, but
`irohad` is excluded from the selected Cargo commands. Package-triggered
external consumers are also deferred. Direct consumer inputs, mixed source
changes, unknown inputs and explicit full runs retain conservative selection.
The JSON report records the tier and every deferred package and consumer.

The same manifest routes the consistency checks (`iroha`, `kagami`), Kotodama
documentation checks (`koto`), and Python network suites (`iroha3d`, `iroha`,
`kagami`) by their affected packages or explicit paths. Binary production
builds only the required union, grouped by feature isolation. Prose-only
changes, including package READMEs, request no release binaries. The Kotodama consumer
uses the canonical `specs/kotodama_v1_docs.json` inventory and the checker's exact fence/heredoc
parser: it compares source bytes and `zk` modes against the PR merge base
(`HEAD` for explicit local paths). Added, changed, deleted, or malformed
executable examples request `koto`; prose edits around unchanged examples do
not. Inventory changes and missing Git/read evidence select the check
conservatively. Required and normative examples belong in the maintained
document inventory.

The Parliament lifecycle corridor is a separately selected consumer. It
declares its existing `qualified_runner` and retains that runner's owned binary
construction and provenance checks. It does not download the PR shipping
bundle. Ordinary prose and foundation-only changes do not run this corridor;
direct corridor inputs, affected non-foundation owners and full selection do.
The required result checks both Rust matrices, binary production,
and every selected consumer, accepting a skipped job only when classification
explicitly did not select it. Classifier failure never becomes a passing skip.

The router fails closed to all lanes for unknown paths, deleted packages,
ambiguous mappings, and shared build inputs. Adding or removing a workspace
member therefore requires an explicit lane-manifest update. The release
workflow continues to run the complete workspace matrix on `main`, tags, and
manual release gates. Apply the `ci/full` label to a pull request to force all
seven routed Rust lanes before merge.

Use the same routing locally:

```sh
scripts/dev_workflow.sh
scripts/dev_workflow.sh --base origin/main
scripts/dev_workflow.sh --full
python3 scripts/rust_ci.py validate
```

## Current documentation

`status.md` summarizes current health and blockers; `roadmap.md` lists remaining
outcomes, owners and completion criteria. Update them when those facts change.
Routine progress and validation results belong in PR descriptions and CI
artifacts. Executable component checks qualify the current source candidate.

## Compile-unit ratchet

The affected execution lane and the full-workspace test gate both run
`scripts/check_compile_unit_budget.py` before their ordinary tests. The guard
compiles the `iroha_data_model` library test graph with the locked dependency
set, writes JSON evidence under `target/ci/`, and enforces the checked-in
`ci/compile_unit_baselines.json` entry with a 2% or three-unit growth allowance,
whichever is larger.

The enforced count deliberately includes only Cargo workspace-member artifacts.
Registry dependencies can legitimately differ across host targets, so using the
all-artifact count as one cross-platform baseline would be unstable. The
workspace-only, library-target scope measures the internal crate graph that the
structural simplification is intended to control. Run the exact CI command when
intentionally refreshing the baseline, review the JSON evidence, and never
raise the baseline merely to make an unexplained regression pass.

Schema-v2 evidence identifies a compile unit by package, target kind and crate
types, source path, sorted features, and the complete Cargo profile, and fails
closed when any identity field is missing. A baseline is usable only when its
scope, manifest, packages, target selection, workspace/locked mode, budget
policy, and exact Rust release match the current command. The PR affected lane
therefore runs the guard with Rust 1.93.1.

## Build-efficiency lineage provenance

`python3 -I -S scripts/check_build_efficiency_provenance.py` verifies the five
pinned implementation, donor, source-budget, protected-integration, and lock
anchor commits from local full-history Git objects. It checks their exact
trees, ordered parents, ancestry, historical Rust counts, and 14 selected path
states before dependency or release Cargo work. The historical
anchor lock remains byte-pinned. The current `HEAD` lock is independently
verified and reported by blob identity and SHA-256, so approved dependency
boundaries can refresh it. Release source seals bind each candidate's lock to
its own artifacts. Schema 4 retains source-budget records only as authenticated
history; candidate source files have no line-count limits.

The anchor's OpenPGP issuer fingerprint is structural metadata bound by the
pinned commit object. No trusted public key is part of this contract, so the
guard does **not** claim cryptographic signer authentication. It disables Git
configuration injection, replacement objects, and lazy fetching; callers must
provide the required history locally. The PR workflow and
`ci/check_sorafs_cli_release.sh` run it before any Cargo work.

## Focused dependency-graph ratchet

`python3 scripts/check_dependency_budget.py` enforces the exact no-growth
limits in `ci/dependency_budget.json`. The checked-in scopes cover source
graphs rooted at the shipping crates `iroha_model_base`, `iroha`, `iroha_data_model`, `irohad`, and
`iroha_cli`, plus a whole-workspace/all-targets scope whose roots include
development dependencies. CI runs this source-only check before classifying
affected Rust lanes, so it does not fetch crates, invoke Cargo, depend on the
host target, or rewrite `Cargo.lock`.

The ratchet resolves workspace inheritance, local path dependencies, and root
path patches directly from the Cargo manifests. “Required” metrics count
non-optional dependency declarations; “declared” metrics include optional
declarations too. Both include normal, build, and target-specific declarations
as a cross-platform upper bound. Development dependencies are included only
for configured roots, matching Cargo's rule that dependency crates do not
contribute their own dev graph. The limits cover local/workspace/path package
counts, unique external package names, and manifest dependency edges. They are
deliberately described as a reproducible source graph: use the compile-unit
guard or an actual Cargo profile when compiler-unit or fully resolved
registry-package evidence is needed.

After reviewing an intentional dependency change, refresh the exact limits with:

```sh
python3 scripts/check_dependency_budget.py \
  --config ci/dependency_budget.json \
  --write-baseline
```

Review the resulting diff and the content-derived manifest fingerprint. Never
raise a limit merely to accept unexplained growth; reductions pass the existing
ceiling and should ratchet it downward in the same change. Required UI/media
stacks listed in `denied_required_packages` cannot be blessed by a refresh.
Any manifest-fingerprint drift fails closed until that dependency change and
the refreshed exact limits are reviewed together.

The foundational model's default and transparent API selections reject
aggregate, privacy/service, HTTP, storage, proof primitive and node execution
paths. Native Pasta/PLONK primitives are shared by the aggregate model and SoraFS
proof-of-possession verifier; wallet relation and recursive proof execution stay
owned by `iroha_kagemusha_proof` and `iroha_plonk_recursion`. Model, SDK, wire and
service selections reject those wallet execution owners. The daemon retains its
mandatory Core ZK verification dependencies. Normal and build dependencies are
both checked; only the explicit aggregate-model test selection includes its root
development dependencies.

`python3 scripts/check_dependency_budget.py --check-boundaries` additionally
enforces the `architecture` layer ownership and shipping configurations in
the same policy file. Each configuration resolves its own Cargo package and
feature selection with `--locked` and includes normal and build dependencies.
Shipping selections exclude development dependencies; the explicit model test
selection includes only its root's development dependencies. The `all` target
selection covers
platform-specific dependencies. The check reports a concrete transitive path
for every forbidden layer or proof-execution feature; a resolution error is
a failure. Use `--offline` after dependencies have been fetched and
`--json-out <path>` to retain evidence. Boundary failures cannot be accepted
with `--write-baseline`. Extend the owned package and configuration inventory
when introducing a new SDK, model, or runtime compilation unit.

`python3 scripts/sdk_operation_inventory.py` checks the complete Torii route
inventory before lane classification. It compiles only the `std`-based route
descriptors and requires no node binaries. The [SDK inventory guide](../docs/sdk_inventory.md)
describes the authentication, transport, and feature metadata used for migration.

For diagnostic comparison with a Cargo-resolved graph, opt in explicitly. The
command remains locked unless `--allow-lock-update` is provided:

```sh
python3 scripts/check_dependency_budget.py \
  --resolved -p iroha_data_model \
  --max-total-packages <reviewed-limit>
```

## Repository structure checks

Five fast, read-only checks keep structural and provisioning debt from returning:

- `python3 scripts/check_compile_time_table_assets.py` verifies the exact size
  and SHA-256 of the versioned binary tables decoded into Rust constants,
  reconstructs every removed declaration from its pinned Git preimage, rejects
  stray binary files, and requires exactly one fixed-size `include_bytes!`
  consumer per asset.
- `python3 scripts/check_cargo_feature_hygiene.py` rejects workspace-wide
  feature injection and implicit default-feature ownership across every
  workspace member. Capability bundles belong to the crate or binary that
  consumes them.
- `python3 scripts/check_workspace_target_inventory.py` keeps ordinary
  workspace builds limited to the first-release shipping executables. Fixture
  generators, probes, benchmarks, and evidence tools require explicit opt-in.
  The standalone SoraFS software signer is release-only and requires the
  `irohad/external-software-signer-bin` feature; the shared daemon-side signer
  protocol remains part of `irohad`'s normal `daemon` feature.
- `python3 scripts/check_generated_artifacts.py` validates
  `generated-files.toml`, requires reproducible ownership for checked-in
  generated source, and rejects tracked build, cache, package, and `dist`
  outputs.
- `python3 scripts/check_nexus_provisioning_templates.py` rejects runtime
  signing keys in production/default Nexus and Taira templates, requires
  dedicated `/run/secrets/iroha` file handles, and checks paired client/server
  exact-network identities.

Their focused regression tests live under `scripts/tests/` and
`pytests/scripts/`; the PR classifier runs them before selecting Rust lanes.

## Reproducible Cargo profiling

Use `scripts/profile_cargo_build.py` to compare compiler work without changing
the repository-local `target/` layout used by CI. The profiler requires its
target, report, caller-private Cargo home, and caller-private Rustup home to be
external and disjoint. It takes bounded, inode-independent copies of the dirty
Git-selected source bytes, Cargo `registry/` and `git/` cache roots, and full
Rustup tree. Cargo runs only from the read-only source snapshot, against the
writable private cache/toolchain copies and private HOME/tmp. It adds
`--locked`, Cargo JSON messages, timing output, and a deterministic job count,
then records the source, lockfile, initial cache/toolchain/warm-target,
environment, PATH/core-tool, and compiled-unit fingerprints alongside
wall-clock and completed-child resource measurements. Cargo, rustc, and Git
are privately copied and byte-bound; other helpers reachable through the
recorded PATH are not copied or byte-authenticated.

After Cargo exits, the profiler re-captures the caller source/HEAD,
`Cargo.lock`, caller cache/toolchain, original and private core tools, and the
private execution source. Git reads have optional locks, fsmonitor,
untracked-cache, hooks, and ambient system/global configuration disabled. Only
top-level `valid: true` reports are comparable; any drift invalidates the
report and makes an otherwise successful profile exit with status 3.

For a cold profile, start with an absent or empty target directory:

```sh
python3 scripts/profile_cargo_build.py \
  --target-dir /tmp/iroha-profile-target \
  --out /tmp/iroha-profile/cold.json \
  --cargo-home "$IROHA_PROFILE_CARGO_HOME" \
  --rustup-home "$IROHA_PROFILE_RUSTUP_HOME" \
  -- build --workspace
```

Both home arguments are required canonical, external, caller-private roots
prepopulated for an offline build. The profiler runs locked and offline,
creates fresh private source/cache/Rustup/HOME/tmp state beside the report,
refuses to replace any report, transcript, or state path, and removes the
private state after validation. Copy limits are 250,000 records, 4 GiB per
file, 64 GiB per tree, depth 128, path length 4096 bytes, and 1 GiB free after
each copy. Special files, hard-linked regular files in writable caller-derived
inputs, and absolute or escaping symlinks are rejected.

Warm profiles require an explicit `--reuse-target` so cached work cannot be
mistaken for a cold measurement; reused targets containing hard-linked files
are rejected and the initial warm target is content-bound in the report.
Allowed manifest paths are remapped into the private source snapshot, and
`--target` accepts target triples rather than paths. Keep the emitted JSON
report, JSONL Cargo
message stream, stderr log, and Cargo timing HTML together when comparing two
revisions. A comparison is meaningful only when the report input fingerprints
and Cargo arguments identify the intended source/toolchain change.

The external target and report bundle are intentional mutable outputs. Input
reads may update filesystem access times. The profiler provides path isolation,
not an OS sandbox: transitive helpers selected from the recorded PATH and
hostile processes already able to address unrelated absolute paths are outside
the guarantee. Authoritative evidence is schema-v4 output from
`scripts/profile_cargo_build.py`.

The read-only `scripts/check_compile_memory_budget.py` compares that evidence
against `ci/compile_memory_budgets.json`. It preserves retained-unit byte limits,
requires 25% lower peaks across the model crates, and enforces the 13-GiB release
ceiling. Complete `--suite` qualification requires every configured surface from
one candidate source/lock revision; pending baselines and failed or cached builds
cannot pass. Four real baselines are pinned; repaired Core/Torii test and daemon
baselines, pinned-runner scheduling and real candidate measurements remain open.
See [the profiling guide](../docs/profile_build.md#measured-memory-acceptance).

### Featured checks
- `check_rust_1_92_lints.sh` – runs `cargo check` with the Rust 1.92 lint set (including the new never-type fallback and macro-export checks) so stricter diagnostics surface before CI.
- `check_swift_spm_validation.sh` – exercises `IrohaSwift/Package.swift` with the bridge present and with the bridge intentionally missing. The complete artifact must build and the missing-artifact case must fail with the mandatory-bridge diagnostic. Writes a summary + logs under `artifacts/swift_spm_validation`.
- SwiftPM is the sole supported Swift packaging path. The mobile artifact
  workflow authenticates the final XCFramework ZIP, checksum inventory and
  package manifest, then compiles the ZIP consumer. Qualify an ordinary public
  `IrohaSwift` dependency in Release with real native execution and no unsafe
  linker flags. The complete host suite, simulator sample, physical-device
  evidence and signed public installation retain separate verdicts.
- `check_walletless_follow_bundle.sh` – repackages the walletless follow-game static bundle and asserts the tarball + `.sha256` sidecar exist. Use this in CI before publishing via the content lane workflow.

## Cargo `build-dir` decision

Rust 1.91 stabilised the `[build] build-dir` option, which allows relocating
`target/`. The workspace baseline is now Rust 1.92, but we audited the CI
wrappers and decided **not** to override this
setting:

- `ci/check_sorafs_fixtures.sh` exports `target/go-cache`, `target/go-mod-cache`,
  and other Go workdirs when it runs the cross-language chunker suite
  (`ci/check_sorafs_fixtures.sh:72-85`). Moving the build directory would break
  those cache paths as well as the `TMPDIR` wiring that assumes they live inside
  the repository.
- `ci/check_norito_enum_bench.sh` writes Criterion artefacts to
  `${ROOT_DIR}/target/criterion` so downstream tooling can scrape the JSON/HTML
  reports without extra configuration (`ci/check_norito_enum_bench.sh:6-27`).

Other scripts (Swift dashboards, Android docs, etc.) stream intermediate files
into `target/` for the same reason: shared caches and human-readable locations.
To keep CI deterministic, **do not** set `[build] build-dir` in
`.cargo/config.toml` and avoid committing `CARGO_TARGET_DIR` overrides. If you
need a custom build directory for local experimentation, export
`CARGO_TARGET_DIR` in your shell session but reset it before running any
`ci/check_*` script.

## Privacy SDK dependency graph

`ci/privacy_sdk_cargo_lockfile.sh` owns the one reviewed Cargo graph digest for
both the workspace and native SDKs. `provision-ci` authenticates the tracked
root lock, creates a separate read-only external snapshot from those exact
bytes, and requires full `cargo metadata --locked` compatibility with the
pinned toolchain before exporting build inputs. It never resolves a new graph
or retries without `--locked`. Every privacy release selection must name the external
file explicitly; root paths, internal paths, symlinks, hardlinks and fallback
selectors are rejected. Root and external file identities remain independently
sealed even though their bytes match. Changed manifests or dependencies require
an explicit graph review, a coherent owner update, and fresh native artifacts;
source, wheel, ABI, hardware and clean-release gates still apply.
Review both lock entries and manifest dependency kinds, target conditions and
features: an unchanged package version inventory does not imply an unchanged
build closure. After an approved graph change, replace the sole digest and
provision a fresh external snapshot; previous graph snapshots remain historical
evidence and cannot authorize new builds. Retain locked metadata validation and
independent root/external identity checks before and after it.

The Python privacy guard includes the five original installed confidential-wallet
native cases before its final artifact/source verification. For retained local
CI evidence, set `PRIVACY_PYTHON_SDK_EVIDENCE_DIR` to a fresh absolute child of
`target/qualification`. The guard copies the original wheels, installed native
extension, artifact manifest, Cargo invocation transcript and JUnit result there
before deleting its disposable build/venv. The receipt reports exact test results;
the outer guard exit also includes final cleanup revalidation. Retention does not
relax the clean committed source requirement or confer independent release or
deployment authority. A missing, skipped or failed native case cannot produce a
passing retained test receipt.

The affected-lane Clippy and Rustdoc checks select every declared feature and
implicit optional-dependency feature through `scripts/rust_ci.py`. The four
`mutation-testing` owners are excluded from non-test compilation because their
selectors belong to the dedicated Sumeragi, Core, Model and daemon mutation jobs.
The same feature matrix serves workspace diagnostics. Defaults, governance,
fixture helpers, simulator coverage and explicitly isolated test-network features
remain selected; this diagnostic matrix does not qualify a shipping feature graph.
A supported feature or dependency that forwards a mutation selector fails before
Cargo starts and requires an explicit ownership review.
