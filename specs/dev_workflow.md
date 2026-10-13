# AGENTS Development Workflow

This runbook consolidates the contributor guardrails from the AGENTS roadmap so
new patches follow the same default gates.

## Quickstart targets

- Run `make dev-workflow` (wrapper around `scripts/dev_workflow.sh`) to execute:
  1. `cargo fmt --all`
  2. `cargo clippy --workspace --all-targets --locked -- -D warnings`
  3. `cargo build --workspace --locked`
  4. `cargo test --workspace --locked`
  5. `swift test` from `IrohaSwift/`
- `cargo test --workspace` is long-running (often hours). For quick iterations,
  use `scripts/dev_workflow.sh --skip-tests` or `--skip-swift`, then run the full
  sequence before shipping.
- If `cargo test --workspace` stalls on build directory locks, rerun with
  `scripts/dev_workflow.sh --target-dir target/codex-tests` (or set
  `CARGO_TARGET_DIR` to an isolated path) to avoid contention.
- All cargo steps use `--locked` to respect the repository policy of keeping
  `Cargo.lock` untouched. Prefer extending existing crates rather than adding
  new workspace members; seek approval before introducing a new crate.

## Guardrails

- `make check-agents-guardrails` (or `ci/check_agents_guardrails.sh`) fails if a
  branch modifies `Cargo.lock`, introduces new workspace members, or adds new
  dependencies. The script compares the working tree and `HEAD` against
  `origin/main` by default; set `AGENTS_BASE_REF=<ref>` to override the base.
- `make check-dependency-discipline` (or `ci/check_dependency_discipline.sh`)
  diffs `Cargo.toml` dependencies against the base and fails on new crates; set
  `DEPENDENCY_DISCIPLINE_ALLOW=<dep1,dep2>` to acknowledge intentional
  additions.
- `make check-missing-docs` (or `ci/check_missing_docs_guard.sh`) blocks new
  `#[allow(missing_docs)]` entries, flags touched crates (nearest `Cargo.toml`)
  whose `src/lib.rs`/`src/main.rs` lack crate-level `//!` docs, and rejects new
  public items without `///` docs relative to the base ref; set
  `MISSING_DOCS_GUARD_ALLOW=1` only with reviewer approval. The guard also
  verifies that `specs/agents/missing_docs_inventory.{json,md}` are fresh;
  regenerate with `python3 scripts/inventory_missing_docs.py`.
- `make check-tests-guard` (or `ci/check_tests_guard.sh`) flags crates whose
  changed Rust functions lack unit-test evidence. The guard maps changed lines
  to functions, passes if crate tests changed in the diff, and otherwise scans
  existing test files for matching function calls so pre-existing coverage
  counts; crates without any matching tests will fail. Set `TEST_GUARD_ALLOW=1`
  only when changes are truly test-neutral and the reviewer agrees.
- `make check-docs-tests-metrics` (or `ci/check_docs_tests_metrics_guard.sh`)
  enforces the roadmap policy that milestones move alongside documentation,
  tests, and metrics/dashboards. When `roadmap.md` changes relative to
  `AGENTS_BASE_REF`, the guard expects at least one doc change, one test change,
  and one metrics/telemetry/dashboard change. Set `DOC_TEST_METRIC_GUARD_ALLOW=1`
  only with reviewer approval.
- `make check-todo-guard` (or `ci/check_todo_guard.sh`) fails when TODO markers
  disappear without accompanying docs/tests changes. Add or update coverage
  when resolving a TODO, or set `TODO_GUARD_ALLOW=1` for intentional removals.
- `make check-std-only` (or `ci/check_std_only.sh`) checks the complete current
  source tree, including unstaged and nonignored new files, for Wasm/WASI
  build/runtime support, WebAssembly artifacts, and `no_std` crate attributes.
  IVM is the only Iroha VM. This gate has no environment override.
- `make check-status-sync` (or `ci/check_status_sync.sh`) keeps the roadmap open
  section free of completed items and requires `roadmap.md`/`status.md` to
  change together so plan/status stay aligned; set
  `STATUS_SYNC_ALLOW_UNPAIRED=1` only for rare status-only typo fixes after
  pinning `AGENTS_BASE_REF`.
- `make check-proc-macro-ui` (or `ci/check_proc_macro_ui.sh`) runs the trybuild
  UI suites for derive/proc-macro crates. Run it when touching proc-macros to
  keep `.stderr` diagnostics stable and catch panicking UI regressions; set
  `PROC_MACRO_UI_CRATES="crate1 crate2"` to focus on specific crates.
- `make check-env-config-surface` (or `ci/check_env_config_surface.sh`) rebuilds
  the env-toggle inventory (`specs/agents/env_var_inventory.{json,md}`),
  fails if it is stale, **and** fails when new production env shims appear
  relative to `AGENTS_BASE_REF` (auto-detected; set explicitly when needed).
  Refresh the tracker after adding/removing env lookups via
  `python3 scripts/inventory_env_toggles.py --json specs/agents/env_var_inventory.json --md specs/agents/env_var_inventory.md`;
  use `ENV_CONFIG_GUARD_ALLOW=1` only after documenting intentional env knobs
  in the migration tracker.
- `make check-serde-guard` (or `ci/check_serde_guard.sh`) regenerates the serde
  usage inventory (`specs/norito_json_inventory.{json,md}`) into a temp
  location, fails if the committed inventory is stale, and rejects any new
  production `serde`/`serde_json` hits relative to `AGENTS_BASE_REF`. Set
  `SERDE_GUARD_ALLOW=1` only for CI experiments after filing a migration plan.
- `make guards` enforces the Norito serialization policy: it denies new
  `serde`/`serde_json` usage, ad-hoc AoS helpers, and retired non-Norito codec
  dependencies in workspace manifests (`scripts/deny_serde_json.sh`,
  `scripts/check_no_direct_serde.sh`, `scripts/deny_handrolled_aos.sh`,
  `scripts/check_no_legacy_codec.sh`). It also runs
  `scripts/check_first_release_history.py`, which checks the
  [first-release history and cutover](first_release_history_cutover.md)
  inventory against the source: one wire version per history type, the listed
  replay and rejection tests, the pinned history fixture, no compatibility
  definition or alias in a history loader, no retired decoder identifier, every
  retired store artifact refusal, and a concrete regeneration target per
  incompatible-change surface. `--report` prints the open findings as
  `path:line`; `--test-commands` prints the `cargo test` commands that run
  exactly the listed tests. `make guards` also runs
  `scripts/check_zk_x509_presentation_interval.py`, which checks the shared
  zk-X509 interval vectors against an independent oracle and the
  [presentation-interval](zk_x509_presentation_interval.md) site inventory
  against the source; `--write` regenerates the vectors. The last guard is
  `scripts/check_zk_resource_contract.py`, which checks the bounds, enforcement
  sites, named tests, relations and scanned scopes of the unified
  [resource contract](zk_resource_contract.json) against the source;
  `--refresh` rewrites the recorded expressions, values and site counts from
  the source and keeps every classification; `--propose` prints skeletons for
  unlisted limits and writes nothing.
- `make check-fhe-ownership` runs `scripts/check_fhe_ownership_map.py` and its
  tests. The script checks `specs/fhe_ownership_inventory.json` against the
  source: every file that names FHE, RAM-LFE or the RAM-LFE HKDF backend, one
  owner per reusable ring-arithmetic primitive with its production callers, and
  one owner for every function of the BFV, RAM-LFE and ZK-AMS owner files.
  After changing a listed file run `make refresh-fhe-ownership`; it recomputes
  the derived facts and leaves new files and functions for you to classify.
  The pull-request workflow runs the same check.
- `make guards` and the pull-request workflow also run
  `scripts/check_zk_operation_inventory.py`. It checks the
  [operation and admission-route inventory](zk_operation_inventory.json)
  against the source: every instruction of the ZK, privacy and FHE families
  with its wire id, handler and authority checks, the twelve-protocol list and
  its dispatch, the thirteen Exact12 roles with the typed dispatch registry
  and the single Exact12 path (one envelope assembler, one instruction, one
  dispatch call, one caller of each native verifier outside its engine, one
  effect consumer), the closed relation, class, job-kind and executable lists, the
  family syscalls and Kotodama builtins, the Torii routes of the listed path
  families, the SDK and native-bridge files and declarations that reference
  them, every call of a verifier or restore-validator entry point with its
  admission route class, the path from each handler to its verifier with the
  tests that reach it, and the sites where a key, source hash or catalog entry
  selects a proof. After adding an instruction, route, verifier call, selector
  site or SDK declaration in those families, list it in the inventory;
  `--propose` prints a skeleton and `--refresh` recomputes the scanned parts
  and keeps every classification.
- `make guards` and the pull-request workflow also run
  `scripts/check_zk_economic_invariants.py`. It checks the
  [protocol economic invariant matrix](zk_economic_invariants.json) against
  the source: every operation of the operation inventory is classified as
  moving value or not, every value-bearing operation has an effect row, and
  each row's handler, enforcement sites and cited tests exist. A handler
  recorded as moving no value fails the check when it starts to name a
  ledger-value identifier. After adding a value-bearing instruction, a ledger
  effect class, a reserve-owning protocol, a root role or a lifecycle state,
  add its row or entry; `--refresh` rewrites recorded lines, the
  suspension-word counts and the summary, and keeps every classification.
  `--show` prints one line per effect and `--defects` one per open defect.
- `make guards` and the pull-request workflow also run
  `scripts/check_zk_primitive_workloads.py`. It checks the
  [primitive and workload specification](zk_primitive_workloads.json) against
  the source: the digest primitives each proof, privacy, FHE, IVM and
  primitive-owner file names (by algorithm name or by a listed wrapper symbol),
  the reviewed digest roles with their symbols, domain literals and compile
  status, the ledger of production functions that call a digest in the catalog,
  Kaigi, spentness, MKHE and privacy-model owners, the carriers of each pinned
  commitment value in any byte form and the files that name a commitment type,
  the candidate native commitment frame and its vectors, the BN254 Poseidon
  tables against an independent regeneration, the post-quantum packages, call
  sites and known-answer responses, the exploratory workload and
  transcript-requirement lists, and the frozen semantic profiles of task H.2:
  each identity is recomputed from its parameters by
  `scripts/zk_semantic_profile_reference.py`, every digest role and H.1 defect
  needs a disposition, the transcript known answers in
  `fixtures/fastpq/q77-transcript-profile.json` are recomputed, and a recorded
  measurement that names another identity than the current one fails as
  inapplicable. A file or function that starts to use a digest
  fails the guard: run `--refresh --write` to record it, then classify a new
  use under its consumer and assign a new producer its role.
  `--write-candidate-vectors`, `scripts/zk_bn254_poseidon_reference.py
  --write-vectors` and `scripts/zk_pq_kat_reference.py --write-inputs`
  regenerate the fixtures the Rust vector tests read.
- **Proc-macro UI policy:** every proc-macro crate must ship a `trybuild`
  harness (`tests/ui.rs` with pass/fail globs) behind the `trybuild-tests`
  feature. Place happy-path samples under `tests/ui/pass`, rejection cases under
  `tests/ui/fail` with committed `.stderr` outputs, and keep diagnostics
  non-panicking and stable. Refresh fixtures with
  `TRYBUILD=overwrite cargo test -p <crate> -F trybuild-tests` (optionally with
  `CARGO_TARGET_DIR=target-codex` to avoid clobbering existing builds) and
  avoid relying on coverage builds (`cfg(not(coverage))` guards are expected).
  For macros that do not emit a binary entrypoint, prefer
  `// compile-flags: --crate-type lib` in fixtures to keep errors focused. Add
  new negative cases whenever diagnostics change.
- CI runs the guardrail scripts via `.github/workflows/agents-guardrails.yml`
  so pull requests fail fast when the policies are violated.
- The sample git hook (`hooks/pre-commit.sample`) runs guardrail, dependency,
  missing-docs, std-only, env-config, and status-sync scripts so contributors
  catch policy violations before CI. Keep TODO breadcrumbs for any intentional
  follow-ups instead of deferring large changes silently.
