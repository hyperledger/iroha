# Integration Tests

This crate hosts cross-component tests for Iroha.

## Running tests
- Default suite: `cargo test -p integration_tests -- --nocapture`
- Grouped harnesses:
  - `core_api`
  - `events_and_triggers`
  - `queries_and_proofs`
  - `network_functional`
  - `consensus_and_da`
  - `sumeragi`
  - `sumeragi_lanes`
  - `sumeragi_npos_committee_transition`
  - `nexus_and_streaming`
- Sumeragi on real peers: `cargo test -p integration_tests --test sumeragi` and
  `--test sumeragi_lanes`; message loss, partitions, crashes and Byzantine
  behavior are covered by the deterministic simulator
  (`cargo test -p iroha_sumeragi --features sim`, `specs/sumeragi.md` §13).
- Target a harness directly with `cargo test -p integration_tests --test <harness>`.
- The focused `taira_consensus_contracts` target in `iroha_test_network` requires four real validators, three public routable lanes, and the exact signed Ordinary transaction to become state-resolved Applied while all four peers advance beyond genesis. It shares the existing multi-route NPoS/DA genesis fixture, keeps production proof defaults, and fails sandbox skips. Prebuild the native `iroha3d` daemon and `iroha` CLI and select them with `TEST_NETWORK_BIN_IROHAD` and `TEST_NETWORK_BIN_IROHA`; set `IROHA_TEST_SKIP_BUILD=1` and run `cargo test --locked -p iroha_test_network --test taira_consensus_contracts four_peer_multiroute_ordinary_transaction_reaches_applied -- --exact --nocapture`. The maintained Taira release gate supplies these binaries from the same warm native build before the Linux build.
- Target a single test with `cargo test -p integration_tests --test <harness> <filter> -- --nocapture`.
- Global candidate admission: `cargo test -p integration_tests --test consensus_and_da sumeragi_npos_candidate::fresh_global_candidate_bonds_before_authenticated_committee_activation -- --exact --nocapture`. This required-network scenario starts four NPoS validators and a separate signed observer, transfers canonical XOR from funded Alice to its ordinary account, rejects foreign peer consent without custody changes, and admits the operator's valid self-bonded candidacy for the E+2 boundary. All five replicas must agree on registration, exact liquid/escrow balances and pending eligibility, while authenticated current finality remains exactly four equal voters and three commit signatures. It fails a sandbox skip. This fee-policy-disabled admission fixture does not qualify fee-enabled quoting, subsequent election, runtime credential installation, observer-to-voter promotion or withdrawal.
- Exact test filters are now module-qualified inside the grouped harnesses; for example:
  `cargo test -p integration_tests --test core_api asset::client_add_asset_quantities_should_increase_asset_amounts -- --exact --nocapture`
- Release acceptance must require its network fixtures instead of accepting sandbox-related skips.
  Run the dynamic-access serialization gate with
  `IROHA_TEST_REQUIRE_NETWORK=1 cargo test -p integration_tests --test core_api contracts::dynamic_and_helper_hidden_contract_writes_serialize_on_four_peers -- --exact --nocapture`.
  The Kotodama/IVM V1 release gate is
  `IROHA_TEST_REQUIRE_NETWORK=1 IROHA_TEST_SERIALIZE_NETWORKS=1 cargo test --locked -p integration_tests --test core_api contracts::contract_v1_executes_and_survives_four_peer_native_finality_restart -- --exact --nocapture --test-threads=1`.
  It authenticates the signed NPoS/mandatory-DA genesis contract, requires
  the independently genesis-anchored native finality chain and exact deployment
  inclusion on every peer, decodes the canonical `int`
  result and persisted state on all four peers, then repeats both reads through
  a cold-restarted validator.
  The pull-request test job sets this switch; ordinary developer runs keep the existing sandbox-skip behavior.
- Generic ZK record/event scenarios use genuine canonical full-unshield keys and
  native wallet proofs over synthetic local trees. Generic proof verification does
  not authorize ledger execution or value movement.
  The focused filters are `proofs::submit_proof_and_query_record` in
  `queries_and_proofs`, `events::proof::proof_event_scenarios` in
  `events_and_triggers`, and `queries::proof::proof_query_scenarios` in
  `queries_and_proofs`. The mixed-backend query scenario requires `--features zk-stark`
  and a daemon built with `zk-stark`; its negative STARK fixture corrupts an actual
  current-profile Binding proof while retaining valid framing and key material.
  All three networks have exactly four validators and retain production proof limits
  and verification deadlines. Require `IROHA_TEST_REQUIRE_NETWORK=1` and
  `IROHA_TEST_SERIALIZE_NETWORKS=1`; prebuild the same-candidate `iroha3d` and `iroha`,
  set their absolute `TEST_NETWORK_BIN_IROHAD` / `TEST_NETWORK_BIN_IROHA` paths, and
  set `IROHA_TEST_SKIP_BUILD=1`. Retain source, lockfile and artifact hashes; explicit
  binary paths alone do not attest candidate identity.
- The explicit full-capacity wallet regression is
  `cargo test --locked -p integration_tests --test queries_and_proofs proofs::full_tree_wallet::four_validator_full_tree_wallet_proof_records_reject_corruption_and_relabelling -- --exact --ignored --nocapture --test-threads=1`
  with the same mandatory-network and same-candidate artifact environment. It builds
  all 65,536 nonzero leaves, proves one actual note through the public
  `ConfidentialProver` API with one membership path, and requires the exact Verified
  record on all four validators. Native proof corruption and relabelling to a distinct
  canonical confidential-transfer key must produce Rejected records on every validator.
  The synthetic root is only a local proof statement: this test submits `VerifyProof`,
  authenticates no ledger asset root, and moves no confidential value. Native proving
  and network execution are expensive, so the scenario is explicitly ignored by default.
- The proof-backed execution rejection gate is
  `cargo test --locked -p integration_tests --test core_api contracts::ivm_proved::four_validator_ivm_proved_rejects_unavailable_execution_and_preserves_state -- --exact --ignored --nocapture --test-threads=1`
  with the same mandatory-network and same-candidate artifact environment. It
  deploys a real Kotodama counter and requires an ordinary authenticated call to
  increment it on all four validators. Each peer must reject IvmProved with the
  exact unavailable-execution-relation reason for empty and nonempty claimed
  overlays and different caller-supplied commitments. Each signed request uses
  its exact fee quote. Typed admission refusals are distinguished from committed
  rejections, whose exact signed transaction and result must converge on every
  peer. A separately Applied barrier and unchanged counter distinguish rejection from
  transport failure or a stalled network. This does not qualify proof-backed
  IVM execution: the complete native execution relation and State-owned anchor
  remain unfinished, and no derive or commitment-binding producer is restored.
- Feature flags: `telemetry` (default), `fault_injection`, `js_host_parity`, `zk-stark`, and the non-shipping `privacy-release-evidence` gate. Enable with `cargo test -p integration_tests --features "<feature list>"`.
- The `js_host_parity` local test runs the Rust fetch owner, the actual Node module through the SDK's authenticated native loader, and the actual C ABI through `ctypes`. Build the current JavaScript native artifact first, then select the rebuilt host bridge directory with `IROHA_NATIVE_LIBRARY_PATH=/absolute/bridge/directory cargo test -p integration_tests --features js_host_parity --test nexus_and_streaming orchestrator_parity_across_runtimes`. `IROHA_PARITY_NODE` and `IROHA_PARITY_PYTHON` can select installed runtimes; absent or stale native artifacts fail the test. Comparisons cover payload bytes, scoreboard weights/eligibility, provider reports, receipts and native-call timing, excluding process startup.
- Norito FEC parity, missing-chunk recovery and corruption tests run in the ordinary `nexus_and_streaming` harness using its local GF(256) helpers; no optional external Reed–Solomon dependency is needed.
- Ignored/long cases (e.g., adversarial network, flaky trigger paths): `IROHA_RUN_IGNORED=1 cargo test -p integration_tests -- --ignored --nocapture`.
- Plain `cargo test` now uses Cargo's native jobserver and libtest's native thread selection; the workspace no longer serializes every developer build or test globally. Memory-constrained and release-evidence wrappers set scoped `--jobs`, `RUST_TEST_THREADS`, debug, and incremental limits only for their own runs.
- High-count integration-test suites in workspace crates use explicit grouped harnesses instead of Cargo's automatic one-file-one-binary discovery, reducing duplicate test binary linking in default workspace runs.
- Test networks run one-at-a-time by default so plain `cargo test` stays stable on WSL and memory-constrained VMs. Increase concurrency with `IROHA_TEST_NETWORK_PARALLELISM=<N>` on high-memory hosts; set `IROHA_TEST_SERIALIZE_NETWORKS=1` to force one-at-a-time startup explicitly.
- `scripts/run_full_tests.sh` now reuses the workspace-built `iroha3d`, `iroha`, and `kagami` binaries when they are available and isolates the integration-test permit directory by default.
- For WSL or memory-constrained VMs, first size WSL memory/swap/host disk headroom appropriately; use `scripts/run_full_tests.sh --wsl-safe --target-dir /tmp/iroha-wsl-tests` only when you still need a conservative local run. This mode runs non-integration workspace tests one package at a time, sets `CARGO_INCREMENTAL=0`, serializes network tests, writes resource snapshots to `<target-dir>/run_full_tests_resources.log`, and refuses to start the next Cargo step when `MemAvailable` is below `4096` MiB unless overridden with `--min-available-mib`.
- For faster local full runs, `scripts/run_full_tests.sh --fast` routes all cargo calls through `scripts/cargo_fast.sh`; add `--fast-zero-debug` and `--no-incremental` when you want the more aggressive local-throughput mode.

## Fixtures

The native SoraFS repair corridor runs with
`IROHA_TEST_REQUIRE_NETWORK=1 cargo test --locked -p integration_tests --test core_api sorafs_repair_ledger:: -- --nocapture`.
The SoraFS scenarios give genesis preexecution and Tokio workers explicit 32 MiB
stacks and configure a 1 GiB storage ceiling per validator through the ordinary
Nexus configuration. This bounds the local test allocation independently of the
capacity of a shared host filesystem. No extra stack environment setting is
required by the tests.
It uses four NPoS voting validators with mandatory DA, submits duplicate
reports and competing claims through different peers, revokes an active owner,
rejects stale completion, and verifies one terminal result plus byte-identical
finalized task/counter/event projections before and after a validator restart.
This is native-ledger qualification; provider storage execution, lease-expiry
timing, slash/appeal orchestration and production evidence require their own
tests and deployment runs.

The orderbook and reserve corridors use the same harness with the filters
`sorafs_orderbook_ledger::` and `sorafs_reserve_ledger::`. They bootstrap provider
ownership through the production pre-genesis configuration, then submit signed
native instructions for policy, funding and custody changes. Both check distinct
transaction races, exact authority failures, balance conservation and matching
finalized projections after a validator restart. Orderbook partial fills and
expiry, elapsed rent collection, and hardware signing remain separate coverage.

- `iroha_test_samples/build.rs` copies the canonical `fixtures/ivm/*.to` files listed in `crates/ivm/prebuilt_samples.txt` into that crate's Cargo `OUT_DIR`, together with the build profile. All consumers use `sample_ivm_path` and `ivm_build_profile_path`; sealed source trees remain read-only and no manual prebuild or source-tree output fallback is used. Fixture regeneration remains a separate compiler-owned task.
- Regenerate SoraFS gateway fixtures: `cargo run -p integration_tests --features dev-tools --bin sorafs-gateway-fixtures -- --out fixtures/sorafs_gateway`.
- Regenerate grouped `nexus_and_streaming` Norito instruction + streaming goldens:
  `cargo run -p integration_tests --features dev-tools --bin refresh_nexus_streaming_fixtures`.

## Notes
- The ignored N=3 smoke requires `atomic-private-settlement-smoke`.
  This test capability enables the common release harness and its CPU SHA3-384
  privacy proof, retaining every native proof and committee check. The ordinary
  `atomic-private-settlement-release` feature supports the explicit CPU fault,
  leakage and benchmark workloads without compiling the smoke entrypoint.
- The retained benchmark session harness owns one warmed network per
  profile/topology/seed. Its control-channel, economic-vector and measurement
  boundary tests are ordinary tests under
  `nexus::atomic_private_settlement_localnet` with the
  `atomic-private-settlement-release` feature. Run that module without
  `--ignored` for the in-process checks. The ignored
  `atomic_private_settlement_real_process_benchmark_session_harness` requires
  the admitted session runner and is not a standalone one-shot benchmark.
  Both profiles use the same N+1 economic movements, including sponsor
  reimbursement; see [native_atomic_settlement.md](../specs/native_atomic_settlement.md).
- The five `nexus::atomic_private_settlement_localnet::benchmark_terminal_`
  regressions in `nexus_and_streaming` exercise the canonical Norito outcome
  envelope, typed completion deadlines, retained request identity and durable
  publication across success, failure and panic. With the
  `atomic-private-settlement-release` feature, run
  `cargo test --locked -p integration_tests --test nexus_and_streaming --features atomic-private-settlement-release benchmark_terminal_ -- --nocapture --test-threads=1`.
  These ordinary tests launch no validators. Python transport controls are in
  `scripts/tests/private_settlement_attempt_accounting_test.py`; their process
  boundaries are synthetic. Neither suite qualifies a real network or benchmark
  campaign. The complete accounting gate is specified in
  [private_settlement.md](../specs/private_settlement.md).
- `scripts/tests/private_settlement_scope_release_test.py` replays complete
  synthetic registered campaigns through the canonical accounting archive and
  release validators. It covers retained predecessor failures, exact requests,
  full-plan fail-fast closure, manifest coverage and recomputed public counts.
  Run it with the repository's ABI-23 native wheel installed in the selected
  Python environment. Missing native ownership is a failure, not a skipped gate.
- `core_api::config::startup_configuration_is_read_only_on_four_validators` reads the explicit startup configuration through native operator authentication on four validators. It requires a signed POST to `/v1/configuration` to fail with HTTP 405 and `method_not_allowed`, and verifies that the complete effective configuration remains unchanged. Runtime HTTP configuration mutation is not supported.
- Native BPNG alias bootstrap retained-Kura coverage lives in
  `tests/alias_registry_bootstrap_network.rs` in `network_functional`. It requires
  four real NPoS validators, native paid SNS quotes/leases routed through the
  universal registry from genesis and an exact-owner bootstrap grant, then restarts the same peers
  with snapshots disabled, Strict Kura and only an additive BPNG dataspace
  catalog entry. It checks exact leases, domains, parameters, balances and
  transaction results, plus original stored SignedBlock execution plans and
  genuine three-of-four CommitQCs before/after replay. Every peer must also
  demonstrate the live static-catalog addition through the SNS account-alias
  parser and retain its exact validated lane catalog and incarnation roots.
  After the second Strict restart it commits a new BPNG successor, proves the
  predecessor hash/height and lane-incarnation link on all four peers, and
  checks the stopped Kura/CommitQC evidence for exactly one appended certified
  BPNG lane block. Missing binaries, networking or persisted evidence fail; no
  success-by-skip is accepted.
  The first paid universal-domain alias precedes the owner bootstrap grant;
  paid dataspace and domain leases then execute before the private catalog entry
  exists. No routing activation parameter or migration carriers are required. Ordinary
  transaction fees are zero from the original test genesis to isolate real SNS
  lease charges, so this is not production-fee qualification. Existing-file-only
  Fast Kura inspection verifies finality without starting a writer; only the
  actual Strict daemon restart qualifies replay.
  The scenario requires a sealed release environment (`IROHA_RELEASE_*`) whose
  previous release-gate runner was removed, so it fails closed until it is ported
  together with the lane storage it inspects. The scenario neither builds child binaries
  nor substitutes a fresh chain/store for retained replay.
- Pipeline block rejection scaffold lives at `tests/pipeline_block_rejected.rs` inside the `core_api` harness and is `#[ignore]` until a deterministic trigger is available.
- Canonical Jindo activation, pre-activation rejection, exact replay, and
  restarted-peer catch-up coverage lives in
  `tests/privacy_exact12_jindo_network.rs` inside the `network_functional`
  harness.
- Canonical native Orchard and PQ-MASP proving, four-peer DA convergence,
  pre-activation and corrupted-proof rejection, stable-nullifier and exact
  transaction replay, failure atomicity, and a fresh nullifier replay through
  the restarted peer to authenticate recovered PQ state live in
  `tests/privacy_exact12_orchard_pq_masp_network.rs`. The fixture builders are
  non-shipping and require the explicit feature. Run the exact release gate
  with
  `TEST_NETWORK_IROHAD_FEATURES=zk-stark IROHA_TEST_REQUIRE_NETWORK=1 IROHA_TEST_SERIALIZE_NETWORKS=1 cargo test --locked -p integration_tests --test network_functional --features 'zk-stark privacy-release-evidence' privacy_exact12_orchard_pq_masp_network::canonical_orchard_and_pq_masp_actions_survive_four_peer_da_replay_and_restart -- --exact --nocapture --test-threads=1`.
- Canonical native Anonymous PGC, VeRange, Bootle/Lantern, FCMP++, and
  private-IVM proving, exact governed activation, independently corrupted
  proofs, cross-profile proof substitution, wrong statement binding,
  pre-activation rejection, exact and stable-state replay, public-state
  atomicity, four-peer DA finality, and restarted-validator recovery live
  in `tests/privacy_exact12_retained_network.rs`. The same suite proves that
  ZK-ACE remains unavailable on every peer and that its production builder
  fails closed without changing public state. Every available-engine setup
  action and proof traverses the production native executor path; the fixture
  builders are non-shipping and require the explicit feature. Run the
  enforced release gate with
  `TEST_NETWORK_IROHAD_FEATURES=zk-stark IROHA_TEST_REQUIRE_NETWORK=1 IROHA_TEST_SERIALIZE_NETWORKS=1 cargo test --locked -p integration_tests --test network_functional --features 'zk-stark privacy-release-evidence' privacy_exact12_retained_network::canonical_retained_exact12_actions_survive_four_peer_adversarial_replay_and_restart -- --exact --nocapture --test-threads=1`.
- The retained positive ZK-AMS/Vega acceptance suite in
  `tests/privacy_exact12_zk_ams_vega_network.rs` covers canonical native
  proving, governed activation, corrupted statement/proof rejection, exact
  replay, four-validator finality, and restarted-validator recovery once both
  compiled profiles are releasable. It remains an enforced release-evidence
  gate (not ignored): while either production profile is unavailable, the
  required-network command must fail at the compiled-profile boundary before
  activation or a passing evidence marker. Run that gate with
  `TEST_NETWORK_IROHAD_FEATURES=zk-stark IROHA_TEST_REQUIRE_NETWORK=1 IROHA_TEST_SERIALIZE_NETWORKS=1 cargo test --locked -p integration_tests --test network_functional --features 'zk-stark privacy-release-evidence' privacy_exact12_zk_ams_vega_network::canonical_zk_ams_and_vega_actions_survive_four_validator_activation_replay_and_restart -- --exact --nocapture --test-threads=1`.
- Governed ZK-X509 trust-anchor, certificate-policy, and signed-CRL dependency
  ordering, unavailable-profile activation refusal, candidate-action refusal,
  exact four-peer convergence of every rejection, substituted
  anchor/policy/CRL candidate references at the outer unavailable-protocol
  boundary, and cold-restart persistence live in
  `tests/privacy_exact12_zk_x509_network.rs`. This gate intentionally asserts
  that the profile remains unavailable until real KAT/resource evidence is
  pinned; it does not claim reference-specific native proof verification and
  must be replaced by canonical acceptance and nullifier-replay coverage when
  the native network action builder is released. Run it with
  `TEST_NETWORK_IROHAD_FEATURES=zk-stark IROHA_TEST_REQUIRE_NETWORK=1 IROHA_TEST_SERIALIZE_NETWORKS=1 cargo test --locked -p integration_tests --test network_functional --features 'zk-stark privacy-release-evidence' privacy_exact12_zk_x509_network::zk_x509_governance_and_unreleased_actions_fail_closed_across_four_peer_restart -- --exact --nocapture --test-threads=1`.
- The complete canonical exact-12 privacy-registry release gate lives in
  `tests/privacy_exact12_activation_network.rs` inside the
  `network_functional` harness. It covers unauthorized and malformed
  registrations, exact activation lead time, three-of-four activation while a
  validator is stopped, cold Proposed-state recovery, metadata-distinct
  duplicate rejection, exact replay rejection, and final restart/catch-up.
  Run it with
  `TEST_NETWORK_IROHAD_FEATURES=zk-stark IROHA_TEST_REQUIRE_NETWORK=1 IROHA_TEST_SERIALIZE_NETWORKS=1 cargo test --locked -p integration_tests --test network_functional --features zk-stark privacy_exact12_activation_network::canonical_exact12_governance_survives_four_peer_activation_replay_and_restart -- --exact --nocapture --test-threads=1`.
- `tests/zk_confidential_localnet.rs` covers only the exclusion of retired
  confidential wires from the instruction registry.
- SoraNet web deploy + public DNS ALIAS/CNAME + NS/DS delegation placeholders coverage lives at `tests/soranet_web_deploy.rs`.
- The generic game-session retained-input release gate lives in
  `tests/native_game_sessions.rs` inside `core_api`. It starts four real
  validators, retains an application checkpoint and jointly certified pending
  controls through a fixed-height challenge, rejects conflicting evidence,
  resolves a withheld reveal with three validators online, and requires the
  restarted fourth validator to recover identical session bytes and dispute
  commitments. It then proves the actual V2 technical-win transcript with the native
  prover, rejects altered proof bytes, submits the complete proof inside a typed
  `SettleGameSessionV1`, checks the exact proof receipt and settlement height on
  all four peers, and rejects duplicate settlement. The compiled profile stays
  unqualified; the test only widens its TxGossip topic to the bounded execution
  transport budget and leaves default transaction and DA limits intact.
  Every convergence check also queries the same finalized height
  from each peer and verifies the BLS CommitQC for the witnessed execution post-state
  root against the locally generated signed genesis committee. This authenticates
  the committed witnessed writes. A test-only native Kura helper then reads each
  peer's complete local WSV checkpoint and commit manifest, validates their exact
  height/block/artifact binding and publication digest, and requires identical
  full WSV hashes. This is local full-world convergence evidence; the QC does not
  sign that complete WSV hash, and the public route is not a full-WSV verifier.
  It uses zero stakes and never bypasses native proof admission.
  The test reserves 32-MiB stacks for its entry and runtime workers, and sets an explicit 1-GiB Nexus storage budget per validator for the finite local workload.
  Finalized ledger-state observations are retained under each peer's
  `game-finality-evidence/`.
  Run with `IROHA_TEST_REQUIRE_NETWORK=1 cargo iroha-fast -- test -p integration_tests --test core_api native_game_sessions::generic_game_pending_inputs_forfeit_and_restart_four_validators -- --exact --ignored --nocapture`.
  A skipped sandbox is an error in this gate. Successful execution is still
  required; source presence does not qualify authenticated state-root
  convergence or proof-backed payouts.

### Parliament timed-OVN deadline/retry corridor

The feature-isolated `sora_parliament_lifecycle_smoke` target includes
`failure_paths::private_ballot_retry::four_validator_private_ballot_deadline_retry_exhaustion_and_restore`.
It registers actual private-ballot sessions, rejects premature failure and old-TLE
reuse, derives registration-deadline NoResult, admits one fresh retry, exhausts
the frozen limit, checks four-peer finality and restores a validator.
It does not replace the sibling proof-valid timed-OVN aggregate-opening test or
provide deployment/audit qualification. Later-phase private deadline retries and
partial-write rollback still need separate four-validator coverage.

Prebuild the same-source native `iroha3d` with `test-network-parliament-signers`
and the ordinary `iroha` CLI; point `TEST_NETWORK_BIN_IROHAD_PARLIAMENT_SIGNERS`
and `TEST_NETWORK_BIN_IROHA` to those exact artifacts. With
`IROHA_TEST_SKIP_BUILD=1 IROHA_TEST_REQUIRE_NETWORK=1 IROHA_TEST_SERIALIZE_NETWORKS=1`,
run `cargo test --locked -p integration_tests --features parliament-test-signers --test sora_parliament_lifecycle_smoke failure_paths::private_ballot_retry::four_validator_private_ballot_deadline_retry_exhaustion_and_restore -- --exact --nocapture --test-threads=1`.
The new scenario rejects an unavailable network even in a developer run; require
network startup for the whole target so sibling optional sandbox skips cannot be
counted as successful qualification. Deterministic test signers are feature
isolated and are not a deployment-selected custody provider.

### Native SoraFS publication lifecycle

`core_api::sorafs_publication::four_peer_publication_replication_retrieval_restart_and_native_repair`
constructs four validators and three native software providers. Signed genesis
establishes admission; ordinary transfers of the actual configured fee asset fund
each distinct provider and worker account. Real reserve funding and capacity
registration precede challenged assignment/completion proofs. Only one provider receives publisher
staging, so the other two must use assignment-authorized source transport. The
scenario verifies public CID bytes, healthy restart, unavailable corrupt payload
after restart, and the production repair worker's finalized completion and readback.
It then executes the actual same-source `sorafs_cli deploy` with an independently
verified saved checkpoint, requires its complete success receipt and asset
readback, and independently challenges the resulting native completion again.
Set `TEST_NETWORK_BIN_SORAFS_CLI` to the absolute prebuilt `sorafs_cli` artifact
built with `cli-orchestrator`; missing CLI artifacts fail before network startup.
Both publication qualification tests fail if the four-validator network cannot
start; an unavailable sandbox cannot produce a passing skip.
Each provider explicitly declares and bounds two GiB for these two small pins;
the test does not preallocate that disk space.
The gateway uses a genuinely signed and acknowledged empty compliance catalog;
its configured optional HTTPS feed is not fetched by this scenario.

The explicit `sorafs_publication_governance` target requires
`parliament-test-signers`. Its
`four_peer_native_publication_repair_and_parliament_revocation` test adds the
shared real seven-body Parliament corridor, then requires a specific admission
denial across provider restart while an unaffected replica still serves bytes.
The reusable corridor lives in `sora_parliament_lifecycle_support.rs`; it funds
registered citizens with signed transfers of the signed-genesis NPoS fee asset.
Its current finality reader validates the independently constructed genesis bundle
and every contiguous embedded certificate, preserving exact four-validator,
three-vote roster authority and per-peer enacted execution comparisons. The
publication target does not collect unrelated mandatory-beacon scenarios.
Those broader Parliament scenarios retain their existing epoch/KAGEMUSHA
assertions and still require migration from retired V2 finality APIs before that
entire separate target can be qualified; the current proof does not expose an
equivalent epoch-authorization projection.
Use the same-source Parliament daemon and ordinary CLI artifacts described above,
`IROHA_TEST_REQUIRE_NETWORK=1`, and exact test filters. Native stream-token quota,
sequencer and reputation deployment adapters remain separate qualification.
Source and unit-test presence do not establish successful network qualification;
the lifecycle and governed revocation tests must both run successfully.
