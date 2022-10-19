Changelog
=========


2.0.0-pre.rc.7
---------

Features
~~~~~~~~
- hyperledger#2338 Add `cargo-all-features` instrumentation.
- hyperledger#2564 Kagami tool algorithm options.
- hyperledger#2490 Implement ffi_export for freestanding functions.
- hyperledger#1891 Validate trigger execution.
- hyperledger#1988 Derive macros for Identifiable, Eq, Hash, Ord.
- hyperledger#2434 FFI bindgen library.
- hyperledger#2073 Prefer ConstString over String for types in blockchain.
- hyperledger#1889 Add domain-scoped triggers.
- hyperledger#2098 Block header queries. #2098: add block header queries
- hyperledger#2467 Add account grant subcommand into iroha_client_cli.
- hyperledger#2301 Add transaction's block hash when querying it.
- hyperledger#2454 Add a build script to the parity-scale-decoder tool.
- hyperledger#2061 Derive macro for filters.
- hyperledger#2228 Add Unauthorized variant to smartcontracts query  error.
- hyperledger#2395 Add panic if genesis cannot be applied.
- hyperledger#2000 Disallow empty names. #2000: Disallow empty names
- hyperledger#2127 Add sanity check to ensure that all data decoded by  `parity_scale_codec` is consumed.
- hyperledger#2360 Make `genesis.json` optional again.
- hyperledger#2053 Add tests to all remaining queries in private  blockchain.
- hyperledger#2381 Unify `Role` registration.
- hyperledger#2053 Add tests to the asset-related queries in private  blockchain.
- hyperledger#2053 Add tests to 'private_blockchain'
- hyperledger#2302 Add 'FindTriggersByDomainId' stub-query.
- hyperledger#1998 Add filters to queries.
- hyperledger#2276 Include current Block hash into BlockHeaderValue.
- hyperledger#2161 Handle id and shared FFI fns.
  * add handle id and implement FFI equivalents of shared traits (Clone, Eq, Ord)
- hyperledger#1638 `configuration` return doc subtree.
- hyperledger#2132 Add `endpointN` proc macro.
- hyperledger#2257 Revoke<Role> emits RoleRevoked event.
- hyperledger#2125 Add FindAssetDefinitionById query.
- hyperledger#1926 Add signal handling and graceful shutdown.
- hyperledger#2161 generate FFI functions for `data_model`
- hyperledger#1149 Block file count does not exceed 1000000 per directory.
- hyperledger#1413 Add API version endpoint.
- hyperledger#2103 support querying for blocks and transactions.  add FindAllTransactions query
- hyperledger#2186 Add transfer ISI for `BigQuantity` and `Fixed`.
- hyperledger#2056 Add a derive proc macro crate for AssetValueType  enum.
- hyperledger#2100 Add query to find all accounts with asset.
- hyperledger#2179 Optimise trigger execution.
- hyperledger#1883 Remove embedded configuration files.
- hyperledger#2004 Forbid `isize` and `usize` from becoming  `IntoSchema`.
- hyperledger#2105 handle query errors in client.
- hyperledger#2050 Add role-related queries.
- hyperledger#1572: Specialized permission tokens.
- hyperledger#2121 Check keypair is valid when constructed.
- hyperledger#2099 Add WASM integration test based on Orillion use-case.
- hyperledger#2003 Introduce Parity Scale Decoder tool.
- hyperledger#1952 Add a TPS benchmark as a standard for optimizations.
- hyperledger#2040 Add integration test with transaction execution  limit.
- hyperledger#1890 Introduce integration tests based on Orillion use-  cases.
- hyperledger#2048 Add toolchain file.
- hyperledger#2100 Add query to find all accounts with asset.
- hyperledger#2179 Optimise trigger execution.
- hyperledger#1883 Remove embedded configuration files.
- hyperledger#2004 Forbid `isize` and `usize` from becoming  `IntoSchema`.
- hyperledger#2105 handle query errors in client.
- hyperledger#2050 Add role-related queries.
- hyperledger#1572: Specialized permission tokens.
- hyperledger#2121 Check keypair is valid when constructed.
- hyperledger#2099 Add WASM integration test based on Orillion use-case.
- hyperledger#2003 Introduce Parity Scale Decoder tool.
- hyperledger#1952 Add a TPS benchmark as a standard for optimizations.
- hyperledger#2040 Add integration test with transaction execution  limit.
- hyperledger#1890 Introduce integration tests based on Orillion use-  cases.
- hyperledger#2048 Add toolchain file.
- hyperledger#2037 Introduce Pre-commit Triggers.
- hyperledger#1621 Introduce By Call Triggers.
- hyperledger#1970 Add optional schema endpoint.
- hyperledger#1620 Introduce time based triggers.
- hyperledger#1918 Implement basic authentication for `client`
- hyperledger#1726 Implement a release PR workflow.
- hyperledger#1815 Make query responses more type-structured.
- hyperledger#1928 implement changelog generation using `gitchangelog`
- hyperledger#1902 Bare metal 4-peer setup script.

  Added a version of setup_test_env.sh that does not require docker-compose and uses the debug build of Iroha.
- hyperledger#1619 Introduce event-based triggers.
- hyperledger#1195 Close a websocket connection cleanly.
- hyperledger#1606 Add ipfs link to domain logo in Domain structure.
- hyperledger#1767 restrict linear memory usage for wasm smartcontracts.
- hyperledger#1766 Wasm permission validation.
- hyperledger#1754 Add Kura inspector CLI.
- hyperledger#1790 Improve performance by using stack-based vectors.
- hyperledger#1425 Wasm helper crate.
- hyperledger#1425 add limits to wasm execution.
- hyperledger#1805 Optional terminal colors for panic errors.
- hyperledger#1749 `no_std` in `data_model`
- hyperledger#1179 Add revoke-permission-or-role instruction.
- hyperledger#1782 make iroha_crypto no_std compatible.
- hyperledger#1425 add wasm runtime.
- hyperledger#1172 Implement instruction events.
- hyperledger#1734 Validate `Name` to exclude whitespaces.
- hyperledger#1144 Add metadata nesting.
- #1210 Block streaming (server side).
- hyperledger#1331 Implement more `Prometheus` metrics.
- hyperledger#1689 Fix feature dependencies. #1261: Add cargo bloat.
- hyperledger#1675 use type instead of wrapper struct for versioned items.
- hyperledger#1643 Wait for peers to commit genesis in tests.
- hyperledger#1678 `try_allocate`
- hyperledger#1216 Add Prometheus endpoint. #1216: initial implementation of metrics endpoint.
- hyperledger#1238 Run-time log-level updates. Created basic `connection` entrypoint-based reloading.
- hyperledger#1652 PR Title Formatting.
- Add the number of connected peers to `Status`

  After your peer unregisters and disconnects another peer,
  your network will hear reconnection requests from the peer.
  All you can know at first is the address whose port number is arbitrary.
  So remember the unregistered peer by the part other than the port number
  and refuse reconnection from there
- Add `/status` endpoint to a specific port.

Fixes
~~~~~
- hyperledger#2422 Hide private keys in configuration endpoint response.
- hyperledger#2492: Fix not all triggers being executed that match an event.
- hyperledger#2504 Fix failing tps benchmark.
- hyperledger#2477 Fix bug when permissions from roles weren't counted.
- hyperledger#2416 Fix lints on macOS arm.
- hyperledger#2457 Fix tests flakiness related to shut down on panic.
- hyperledger#2473 parse rustc --version instead of RUSTUP_TOOLCHAIN.
- hyperledger#1480 Shut down on panic. #1480: Add panic hook to exit program on panic
- hyperledger#2376 Simplified Kura, no async, two files.
- hyperledger#1649 remove `spawn` from `do_send`
- hyperledger#2128 Fix `MerkleTree` construction and iteration.
- hyperledger#2137 Prepare tests for multiprocess context.
- hyperledger#2227 Implement Register and Unregister for Asset.
- hyperledger#2081 Fix role granting bug.
- hyperledger#2358 Add release with debug profile.
- hyperledger#2294 Add flamegraph generation to oneshot.rs.
- hyperledger#2202 Fix total field in query response.
- hyperledger#2081 Fix the test case to grant the role.
- hyperledger#2017 Fix role unregistration.
- hyperledger#2303 Fix docker-compose' peers doesn't get gracefully shut down.
- hyperledger#2295 Fix unregister trigger bug.
- hyperledger#2282 improve FFI derives from getset implementation.
- hyperledger#1149 Remove nocheckin code.
- hyperledger#2232 Make Iroha print meaningful message when genesis has too many isi.
- hyperledger#2170 Fix build in docker container on M1 machines.
- hyperledger#2215 Make nightly-2022-04-20 optional for `cargo build`
- hyperledger#1990 Enable peer startup via env vars in the absence of config.json.
- hyperledger#2081 Fix role registration.
- hyperledger#1640 Generate config.json and genesis.json.
- hyperledger#1716 Fix consensus failure with f=0 cases.
- hyperledger#1845 Non-mintable assets can be minted once only.
- hyperledger#2005 Fix `Client::listen_for_events()` not closing WebSocket stream.
- hyperledger#1623 Create a RawGenesisBlockBuilder.
- hyperledger#1917 Add easy_from_str_impl macro.
- hyperledger#1990 Enable peer startup via env vars in the absence of config.json.
- hyperledger#2081 Fix role registration.
- hyperledger#1640 Generate config.json and genesis.json.
- hyperledger#1716 Fix consensus failure with f=0 cases.
- hyperledger#1845 Non-mintable assets can be minted once only.
- hyperledger#2005 Fix `Client::listen_for_events()` not closing WebSocket stream.
- hyperledger#1623 Create a RawGenesisBlockBuilder.
- hyperledger#1917 Add easy_from_str_impl macro.
- hyperledger#1922 Move crypto_cli into tools.
- hyperledger#1969 Make the `roles` feature part of the default feature set.
- hyperledger#2013 Hotfix CLI args.
- hyperledger#1897 Remove usize/isize from serialization.
- hyperledger#1955 Fix possibility to pass `:` inside `web_login`
- hyperledger#1943 Add query errors to the schema.
- hyperledger#1939 Proper features for `iroha_config_derive`.
- hyperledger#1908 fix zero value handling for telemetry analysis script.
- hyperledger#0000 Make implicitly ignored doc-test explicitly ignored.
- hyperledger#1865 use latest smallstr to be able to build no_std wasm smartcontracts.
- hyperledger#1848 Prevent public keys from being burned to nothing.
- hyperledger#1811 added tests and checks to dedup trusted peer keys.
- hyperledger#1821 add IntoSchema for MerkleTree and VersionedValidBlock, fix HashOf and SignatureOf schemas.
- hyperledger#1819 Remove traceback from error report in validation.
- hyperledger#1774 log exact reason for validation failures.
- hyperledger#1714 Compare PeerId only by key.
- hyperledger#1788 Reduce memory footprint of `Value`.
- hyperledger#1804 fix schema generation for HashOf, SignatureOf, add test to ensure no schemas are missing.
- hyperledger#1802 Logging readability improvements.
  - events log moved to trace level
  - ctx removed from log capture
  - terminal colors are made optional (for better log output to files)
- hyperledger#1783 Fixed torii benchmark.
- hyperledger#1772 Fix after #1764.
- hyperledger#1755 Minor fixes for #1743, #1725.
  * Fix JSONs according to #1743 `Domain` struct change
- hyperledger#1751 Consensus fixes. #1715: Consensus fixes to handle high load (#1746)
  * View change handling fixes
  - View change proofs made independent of particular transaction hashes
  - Reduced message passing
  - Collect view change votes instead of sending messages right away (improves network resilience)
  - Fully use Actor framework in Sumeragi (schedule messages to self instead of task spawns)
  * Improves fault injection for tests with Sumeragi
  - Brings testing code closer to production code
  - Removes overcomplicated wrappers
  - Allows Sumeragi use actor Context in test code
- hyperledger#1734 Update genesis to fit the new Domain validation.
- hyperledger#1742 Concrete errors returned in `core` instructions.
- hyperledger#1404 Verify fixed.
- hyperledger#1636 Remove `trusted_peers.json` and `structopt`
  #1636: Remove `trusted_peers.json`.
- hyperledger#1706 Update `max_faults` with Topology update.
- hyperledger#1698 Fixed public keys, documentation and error messages.
- Minting issues (1593 and 1405) issue 1405

Refactor
~~~~~~~~
- hyperledger#2468 Remove debug supertrait from permission validators.
- hyperledger#2419 Remove explicit `drop`s.
- hyperledger#2253 Add `Registrable` trait to `data_model`
- impl `Origin` instead of `Identifiable` for the data events.
- hyperledger#2369 Refactor permission validators.
- hyperledger#2307 Make `events_sender` in `WorldStateView` non- optional.
- hyperledger#1985 Reduce size of `Name` struct.
- Add more `const fn`.
- Make integration tests use `default_permissions()`
- add permission token wrappers in private_blockchain.
- hyperledger#2292 Remove `WorldTrait`, remove generics from `IsAllowedBoxed`
- hyperledger#2204 Make Asset-related operations generic.
- hyperledger#2233 Replace `impl` with `derive` for `Display` and `Debug`.
- Identifiable structure improvements.
- hyperledger#2323 Enhance kura init error message.
- hyperledger#2238 Add peer builder for tests.
- hyperledger#2011 More descriptive config params.
- hyperledger#1896 Simplify `produce_event` implementation.
- Refactor around `QueryError`.
- Move `TriggerSet` to `data_model`.
- hyperledger#2145 refactor client's `WebSocket` side, extract pure data logic.
- remove `ValueMarker` trait.
- hyperledger#2149 Expose `Mintable` and `MintabilityError` in `prelude`
- hyperledger#2144 redesign client's http workflow, expose internal api.
- Move to `clap`.
- Create `iroha_gen` binary, consolidating docs, schema_bin.
- hyperledger#2109 Make `integration::events::pipeline` test stable.
- hyperledger#1982 encapsulate access to `iroha_crypto` structures.
- Add `AssetDefinition` builder.
- Remove unnecessary `&mut` from the API.
- encapsulate access to data model structures.
- hyperledger#2144 redesign client's http workflow, expose internal api.
- Move to `clap`.
- Create `iroha_gen` binary, consolidating docs, schema_bin.
- hyperledger#2109 Make `integration::events::pipeline` test stable.
- hyperledger#1982 encapsulate access to `iroha_crypto` structures.
- Add `AssetDefinition` builder.
- Remove unnecessary `&mut` from the API.
- encapsulate access to data model structures.
- Core, `sumeragi`, instance functions, `torii`
- hyperledger#1903 move event emission to `modify_*` methods.
- Split `data_model` lib.rs file.
- add wsv reference to quueue.
- hyperledger#1210 Split event stream.
- hyperledger#1725 Remove global state in Torii.
- Fix linter error.
- hyperledger#1661 `Cargo.toml` cleanup.
- hyperledger#1650 tidy up `data_model`
- Organisation of `json` files and readme. Updated Readme to conform to template.
- 1529: structured logging.
- `iroha_p2p`

Documentation
~~~~~~~~~~~~~
- Generate changelog for pre-rc.7.
- Flakyness report for Jul 30.
- Bump versions.
- Update test flakyness.
- hyperledger#2499 Fix client_cli error messages.
- hyperledger#2344 Generate CHANGELOG for 2.0.0-pre-rc.5-lts.
- Add links to the tutorial.
- Update information on git hooks.
- flakyness test writeup.
- hyperledger#2193 Update Iroha client documentation.
- hyperledger#2193 Update Iroha CLI documentation.
- hyperledger#2193 Update README for macro crate.
- hyperledger#2193 Update README for wasm crate.
- hyperledger#2193 Update Parity Scale Decoder Tool documentation.
- hyperledger#2193 Update Kagami documentation.
- hyperledger#2193 Update benchmarks documentation.
- hyperledger#2192 Review contributing guidelines.
- Fix broken in-code references.
- hyperledger#1280 Document Iroha metrics.
- hyperledger#2119 Add guidance on how to hot reload Iroha in a Docker  container.
- hyperledger#2181 Review README.
- hyperledger#2113 Document features in Cargo.toml files.
- hyperledger#2177 Clean up gitchangelog output.
- hyperledger#1991 Add readme to Kura inspector.
- hyperledger#2119 Add guidance on how to hot reload Iroha in a Docker  container.
- hyperledger#2181 Review README.
- hyperledger#2113 Document features in Cargo.toml files.
- hyperledger#2177 Clean up gitchangelog output.
- hyperledger#1991 Add readme to Kura inspector.
- generate latest changelog.
- Generate changelog.
- Update outdated README files.
- Added missing docs to `api_spec.md`.
- add wasm README.

CI/CD changes
~~~~~~~~~~~~~
- hyperledger#2158 Upgrade `parity_scale_codec`
- Bump trivial dependencies.
- Update `syn`.
- move coverage to a new workflow.
- reverse docker login ver.
- Remove the version specification of `archlinux:base-devel`
- Update Dockerfiles & Codecov reports reuse & Concurrency.
- Generate changelog.
- Add `cargo deny` file.
- Add `iroha2-lts` branch with workflow copied from `iroha2`
- hyperledger#2393 Bump the version of the Docker base image.
- hyperledger#1658 Add documentation check.
- Version bump of crates and remove unused dependencies.
- Remove unnecessary coverage reporting.
- hyperledger#2222 Split tests by whether it involves coverage or not.
- hyperledger#2153 Fix #2154.
- Version bump all of the crates.
- Fix deploy pipeline.
- hyperledger#2153 Fix coverage.
- Add genesis check and update documentation.
- Bump rust, mold and nightly to 1.60, 1.2.0 and 1.62 respectively.
- load-rs triggers.
- hyperledger#2153 Fix #2154.
- Version bump all of the crates.
- Fix deploy pipeline.
- hyperledger#2153 Fix coverage.
- Add genesis check and update documentation.
- Bump rust, mold and nightly to 1.60, 1.2.0 and 1.62respectively.
- load-rs triggers.
- load-rs:release workflow triggers.
- Fix push workflow.
- Add telemetry to default features.
- add proper tag to push workflow on main.
- fix failing tests.
- hyperledger#1657 Update image to rust 1.57. #1630: Move back to self-hosted runners.
- CI improvements.
- Switched coverage to use `lld`.
- CI Dependency Fix.
- CI segmentation improvements.
- Uses a fixed Rust version in CI.
- Fix Docker publish and iroha2-dev push CI.
- Remove unnecessary full Iroha build in CI docker test.
- Adds supports for iroha2 branch in CI pipeline.
- Additional CI caches.

Web-Assembly
~~~~~~~~~~~~
- Fix return value for QueryBox execution in wasm.
- Produce events while executing wasm smartcontract.

Version bumps
~~~~~~~~~~~~~
- Pre-release preparations.
- Update Mold 1.0.
- Bump dependencies.
- Update api_spec.md: fix request/response bodies.
- Update rust version to 1.56.0.
- Update contributing guide.
- Updated README.md and `iroha/config.json` to match new API and URL  format.
- Update docker publish target to hyperledger/iroha2 #1453.
- Updates workflow so that it matches main.
- Update api spec and fix health endpoint.
- Rust update to 1.54.
- Docs(iroha_crypto): update `Signature` docs and align args of `verify`
- Ursa version bump from 0.3.5 to 0.3.6.
- Update workflows to new runners.
- Update dockerfile for caching and faster ci builds.
- Update libssl version.
- Update dockerfiles and async-std.
- Fix updated clippy.
- Updates asset structure.
  - Support for key-value instructions in asset
  - Asset types as an enum
  - Overflow vulnerability in asset ISI fix
- Updates contributing guide.
- Update out of date lib.
- Update whitepaper and fix linting issues.
- Update the cucumber_rust lib.
- README updates for key generation.
- Update Github Actions workflows.
- Update Github Actions workflows.
- Update requirements.txt.
- Update common.yaml.
- Docs updates from Sara.
- Update instruction logic.
- Update whitepaper.
- Updates network functions description.
- Update whitepaper based on comments.
- Separation of WSV update and migration to Scale.
- Update gitignore.
- Update slightly description of kura in WP.
- Update description about kura in whitepaper.

Schema
~~~~~~
- hyperledger#2114 Sorted collections support in schemas.
- hyperledger#2108 Add pagination.
- hyperledger#2114 Sorted collections support in schemas.
- hyperledger#2108 Add pagination.
- Make schema, version and macro no_std compatible.
- Fix signatures in schema.
- Altered  representation of `FixedPoint` in schema.
- Added `RawGenesisBlock` to schema introspection.
- Changed object-models to create schema IR-115.

Tests
~~~~~
- hyperledger#2272 Add tests for 'FindAssetDefinitionById' query.
- Add `roles` integration tests.
- Standardise ui tests format, move derive ui tests to derive crates.
- Fix mock tests (futures unordered bug).
- Removed the DSL crate & moved tests to `data_model`
- Ensure that unstable network tests pass for valid code.
- Added tests to iroha_p2p.
- Captures logs in tests unless test fails.
- Add polling for tests and fix rarely breaking tests.
- Tests parallel setup.
- Remove root from iroha init and iroha_client tests.
- Fix tests clippy warnings and adds checks to ci.
- Fix `tx` validation errors during benchmark tests.
- hyperledger#860: Iroha Queries and tests.
- Iroha custom ISI guide and Cucumber tests.
- Add tests for no-std client.
- Bridge registration changes & tests.
- Consensus tests with network mock.
- Usage of temp dir for tests execution.
- Benches tests positive cases.
- Initial Merkle Tree functionality with tests.
- Fixed tests and World State View initialization.

Other
~~~~~
- Add more details in `Find` error description.
- Fix `PartialOrd` and `Ord` implementations.
- Use `rustfmt` instead of `cargo fmt`
- Remove `roles` feature.
- Use `rustfmt` instead of `cargo fmt`
- Share workdir as a volume with dev docker instances.
- Remove Diff associated type in Execute.
- Use custom encoding instead of multival return.
- Remove serde_json as iroha_crypto dependency.
- Allow only known fields in version attribute.
- Clarify different ports for endpoints.
- Remove `Io` derive.
- Initial documentation of key_pairs.
- Move back to self-hosted runners.
- Fix new clippy lints in the code.
- Remove i1i1 from maintainers.
- Add actor doc and minor fixes.
- Poll instead of pushing latest blocks.
- Transaction status events tested for each of 7 peers.
- `FuturesUnordered` instead of `join_all`
- Switch to GitHub Runners.
- Use VersionedQueryResult vs QueryResult for /query endpoint.
- Reconnect telemetry.
- Fix dependabot config.
- Add commit-msg git hook to include signoff.
- Fix the push pipeline.
- Upgrade dependabot.
- Detect future timestamp on queue push.
- hyperledger#1197: Kura handles errors.
- Add Unregister peer instruction.
- Add optional nonce to distinguish transactions. Close #1493.
- Removed unnecessary `sudo`.
- Metadata for domains.
- Fix the random bounces in `create-docker` workflow.
- Added `buildx` as suggested by the failing pipeline.
- hyperledger#1454: Fix query error response with specific status code and hints.
- hyperledger#1533: Find transaction by hash.
- Fix `configure` endpoint.
- Add boolean-based asset mintability check.
- Addition of typed crypto primitives and migration to type-safe cryptography.
- Logging improvements.
- hyperledger#1458: Add actor channel size to config as `mailbox`.
- hyperledger#1451: Add warning about misconfiguration if `faulty_peers = 0` and `trusted peers count > 1
- Add handler for getting specific block hash.
- Added new query FindTransactionByHash.
- hyperledger#1185: Change crates name and path.
- Fix logs and general improvements.
- hyperledger#1150: Group 1000 blocks into each file
- Queue stress test.
- Log level fix.
- Add header specification to client library.
- Queue panic failure fix.
- Fixup queue.
- Fixup dockerfile release build.
- Https client fixup.
- Speedup ci.
- 1. Removed all ursa dependences, except for iroha_crypto.
- Fix overflow when subtracting durations.
- Make fields public in client.
- Push Iroha2 to Dockerhub as nightly.
- Fix http status codes.
- Replace iroha_error with thiserror, eyre and color-eyre.
- Substitute queue with crossbeam one.
- Remove some useless lint allowences.
- Introduces metadata for asset definitions.
- Removal of arguments from test_network crate.
- Remove unnecessary dependencies.
- Fix iroha_client_cli::events.
- hyperledger#1382: Remove old network implementation.
- hyperledger#1169: Added precision for assets.
- Improvements in peer start up.

  - Allows loading genesis public key only from env
  - config, genesis and trusted_peers path can now be specified in cli params
- hyperledger#1134: Integration of Iroha P2P.
- Change query endpoint to POST instead of GET.
- Execute on_start in actor synchronously.
- Migrate to warp.
- Rework commit with broker bug fixes.
- Revert "Introduces multiple broker fixes"

  This reverts commit 9c148c33826067585b5868d297dcdd17c0efe246.
- Introduces multiple broker fixes.

  1. Unsubscribe from broker on actor stop
  2. Support multiple subscriptions from the same actor type (previously a TODO)
  3. Fix a bug where broker always put self as an actor id.
- Broker bug (test showcase).
- Add derives for data model.
- Remove rwlock from torii.
- OOB Query Permission Checks.
- hyperledger#1272: Implementation of peer counts,
- Recursive check for query permissions inside of instructions.
- Schedule stop actors.
- hyperledger#1165: Implementation of peer counts.
- Check query permissions by account in torii endpoint.
- Removed exposing CPU and memory usage in system metrics.
- Replace JSON with SCALE for WS messages.
- Store proof of view changes.
- hyperledger#1168: Added logging if transaction does not passed signature check condition.
- Fixed small issues, added connection listen code.
- Introduce network topology builder.
- Implement P2P network for Iroha.
- Adds block size metric.
- PermissionValidator trait renamed to IsAllowed.
  and corresponding other name changes
- API spec web socket corrections.
- Removes unnecessary dependencies from docker image.
- Fmt uses Crate import_granularity.
- Introduces Generic Permission Validator.
- Migrate to actor framework.
- Change broker design and add some functionality to actors.
- Configures codecov status checks.
- Uses source based coverage with grcov.
- Fixed multiple build-args format and redeclared ARG for intermediate
  build containers.
- Introduces SubscriptionAccepted message.
- Remove zero-value assets from accounts after operating upon.
- Fixed docker build arguments format.
- Fixed error message if child block not found.
- Added vendored OpenSSL to build, fixes pkg-config dependency.

- Fix repository name for dockerhub and coverage diff.
- Added clear error text and filename if TrustedPeers could not be
  loaded.
- Changed text entities to links in docs.
- Fix wrong username secret in Docker publish.
- Fix small typo in whitepaper.
- Allows mod.rs usage for better file structure.
- Move main.rs into separate crate and make permissions for public
  blockchain.
- Add querying inside client cli.
- Migrate from clap to structopts for cli.
- Limit telemetry to unstable network test.
- Move traits to smartcontracts module.
- Sed -i "s/world_state_view/wsv/g"
- Move smart contracts into separate module.
- Iroha network content length bugfix.
- Adds task local storage for actor id.

  Useful for deadlock detection.

  Also adds deadlock detection test to CI
- Add Introspect macro.
- Disambiguates workflow names.

  also formatting corrections
- Change of query api.
- Migration from async-std to tokio.
- Add analyze of telemetry to ci.
- Add futures telemetry for iroha.
- Add iroha futures to every async function.
- Add iroha futures for observability of number of polls.
- Manual deploy and configuration added to README.
- Reporter fixup.
- Add derive Message macro.
- Add simple actor framework.
- Add dependabot configuration.
- Add nice panic and error reporters.
- Rust version migration to 1.52.1 and corresponding fixes.
- Spawn blocking CPU intensive tasks in separate threads.
- Use unique_port and cargo-lints from crates.io.
- Fix for lockfree WSV.

  - removes unnecessary Dashmaps and locks in API
  - fixes bug with excessive number of blocks created (rejected transactions were not recorded)
  - Displays full error cause for errors
- Add telemetry subscriber.
- Queries for roles and permissions.
- Move blocks from kura to wsv.
- Change to lock-free data structures inside wsv.
- Network timeout fix.
- Fixup health endpoint.
- Introduces Roles.
- Add push docker images from dev branch.
- Add more agressive linting and remove panics from code.
- Rework of Execute trait for instructions.
- Remove old code from iroha_config.
- IR-1060 Adds Grant checks for all the existing permissions.
- Fix ulimit and timeout for iroha_network.
- Ci timeout test fix.
- Remove all assets when their definition was removed.
- Fix wsv panic at adding asset.
- Remove Arc and Rwlock for channels.
- Iroha network fixup.
- Permission Validators use references in checks.
- Grant Instruction.
- Added configuration for string length limits and validation of id's
  for NewAccount, Domain and AssetDefinition IR-1036.
- Substitute log with tracing lib.
- Add ci check for docs and deny dbg macro.
- Introduces grantable permissions.
- Add iroha_config crate.
- Add @alerdenisov as a code owner to approve all incoming merge
  requests.
- Fix of transaction size check during consensus.
- Revert upgrading of async-std.
- Replace some consts with power of 2 IR-1035.
- Add query to retrieve transaction history IR-1024.
- Add validation of permissions for store and restructure of permission
  validators.
- Add NewAccount for account registration.
- Add types for asset definition.
- Introduces configurable metadata limits.
- Introduces transaction metadata.
- Add expressions inside queries.
- Add lints.toml and fix warnings.
- Separate trusted_peers from config.json.
- Fix typo in URL to Iroha 2 community in Telegram.
- Fix clippy warnings.
- Introduces key-value metadata support for Account.
- Add versioning of blocks.
- Fixup ci linting repetitions.
- Add mul,div,mod,raise_to expressions.
- Add into_v* for versioning.
- Substitute Error::msg with error macro.
- Rewrite iroha_http_server and rework torii errors.
- Upgrades SCALE version to 2.
- Whitepaper versioning description.
- Infallable pagination.

  Fix the cases when pagination may unnecessary through errors, not returns empty collections instead.
- Add derive(Error) for enums.
- Fix nightly version.
- Add iroha_error crate.
- Versioned messages.
- Introduces container versioning primitives.
- Fix benchmarks.
- Add pagination.
- Add varint encoding decoding.
- Change query timestamp to u128.
- Add RejectionReason enum for pipeline events.
- Removes outdated lines from genesis files.

  The destination was removed from register ISI in previous commits.
- Simplifies register and unregister ISIs.
- Fix commit timeout not being sent in 4 peer network.
- Topology shuffle at change view.
- Add other containers for FromVariant derive macro.
- Add MST support for client cli.
- Add FromVariant macro and cleanup codebase.
- Add i1i1 to code owners.
- Gossip transactions.
- Add length for instructions and expressions.
- Add docs to block time and commit time parameters.
- Replaced Verify and Accept traits with TryFrom.
- Introduce waiting only for the minimum number of peers.
- Add github action to test api with iroha2-java.
- Add genesis for docker-compose-single.yml.
- Default signature check condition for account.
- Add test for account with multiple signatories.
- Add client API support for MST.
- Build in docker.
- Add genesis to docker compose.
- Introduce Conditional MST.
- Add wait_for_active_peers impl.
- Add test for isahc client in iroha_http_server.
- Client API spec.
- Query execution in Expressions.
- Integrates expressions and ISIs.
- Expressions for ISI.
- Fix account config benchmarks.
- Add account config for client.
- Fix ``submit_blocking``.
- Pipeline events are sent.
- Iroha client web socket connection.
- Events separation for pipeline and data events.
- Integration test for permissions.
- Add permission checks for burn and mint.
- Unregister ISI permission.
- Fix benchmarks for world struct PR.
- Introduce World struct.
- Implement the genesis block loading component.
- Introduce genesis account.
- Introduce permissions validator builder.
- Add labels to Iroha2 PRs with Github Actions.
- Introduce Permissions Framework.
- Queue tx tx number limit and Iroha initialization fixes.
- Wrap Hash in a struct.
- Improve log level:

  - Add info level logs to consensus.
  - Mark network communication logs as trace level.
  - Remove block vector from WSV as it is a duplication and it showed all the blockchain in logs.
  - Set info log level as default.
- Remove mutable WSV references for validation.
- Heim version increment.
- Add default trusted peers to the config.
- Client API migration to http.
- Add transfer isi to CLI.
- Configuration of Iroha Peer related Instructions.
- Implementation of missing ISI execute methods and test.
- Url query params parsing
- Add ``HttpResponse::ok()``, ``HttpResponse::upgrade_required(..)``
- Replacement of old Instruction and Query models with Iroha DSL
  approach.
- Add BLS signatures support.
- Introduce http server crate.
- Patched libssl.so.1.0.0 with symlink.
- Verifies account signature for transaction.
- Refactor transaction stages.
- Initial domains improvements.
- Implement DSL prototype.
- Improve Torii Benchmarks: disable logging in benchmarks, add success ratio assert.
- Improve test coverage pipeline: replaces ``tarpaulin`` with ``grcov``,
  publish test coverage report to ``codecov.io``.
- Fix RTD theme.
- Delivery artifacts for iroha subprojects.
- Introduce ``SignedQueryRequest``.
- Fix a bug with signature verification.
- Rollback transactions support.
- Print generated key-pair as json.
- Support ``Secp256k1`` key-pair.
- Initial support for different crypto algorithms.
- DEX Features.
- Replace hardcoded config path with cli param.
- Bench master workflow fix.
- Docker event connection test.
- Iroha Monitor Guide and CLI.
- Events cli improvements.
- Events filter.
- Event connections.
- Fix in master workflow.
- Rtd for iroha2.
- Merkle tree root hash for block transactions.
- Publication to docker hub.
- CLI functionality for Maintenance Connect.
- CLI functionality for Maintenance Connect.
- Eprintln to log macro.
- Log improvements.
- IR-802 Subscription to blocks statuses changes.
- Events sending of transactions and blocks.
- Moves Sumeragi message handling into message impl.
- General Connect Mechanism.
- Extract Iroha domain entities for no-std client.
- Transactions TTL.
- Max transactions per block configuration.
- Store invalidated blocks hashes.
- Synchronize blocks in batches.
- Configuration of connect functionality.
- Connect to Iroha functionality.
- Block validation corrections.
- Block synchronization: diagrams.
- Connect to Iroha functionality.
- Bridge: remove clients.
- Block synchronization.
- AddPeer ISI.
- Commands to Instructions renaming.
- Simple metrics endpoint.
- Bridge: get registered bridges and external assets.
- Docker compose test in pipeline.
- Not enough votes Sumeragi test.
- Block chaining.
- Bridge: manual external transfers handling.
- Simple Maintenance endpoint.
- Migration to serde-json.
- Demint ISI.
- Add bridge clients, AddSignatory ISI, and CanAddSignatory permission.
- Sumeragi: peers in set b related TODO fixes.
- Validates the block before signing in Sumeragi.
- Bridge external assets.
- Signature validation in Sumeragi messages.
- Binary asset-store.
- Replace PublicKey alias with type.
- Prepare crates for publishing.
- Minimum votes logic inside NetworkTopology.
- TransactionReceipt validation refactoring.
- OnWorldStateViewChange trigger change: IrohaQuery instead of
  Instruction.
- Separate construction from initialization in NetworkTopology.
- Add Iroha Special Instructions related to Iroha events.
- Block creation timeout handling.
- Glossary and How-to add Iroha Module docs.
- Replace hardcoded bridge model with origin Iroha model.
- Introduce NetworkTopology struct.
- Add Permission entity with transformation from Instructions.
- Sumeragi Messages in the message module.
- Genesis Block functionality for Kura.
- Add README files for Iroha crates.
- Bridge and RegisterBridge ISI.
- Initial work with Iroha changes listeners.
- Injection of Permission checks into OOB ISI.
- Docker multiple peers fix.
- Peer to peer docker example.
- Transaction Receipt handling.
- Iroha Permissions.
- Module for Dex and crates for Bridges.
- Fix integration test with asset creation with several peers.
- Re-implement of Asset model into EC-S-.
- Commit timeout handling.
- Block header.
- ISI related methods for domain entities.
- Kura Mode enumeration and Trusted Peers configuration.
- Documentation linting rule.
- Add CommittedBlock.
- Decoupling kura from ``sumeragi``.
- Check that transactions are not empty before block creation.
- Re-implement Iroha Special Instructions.
- Benchmarks for transactions and blocks transitions.
- Transactions lifecycle and states reworked.
- Blocks lifecycle and states.
- Fix validation bug, ``sumeragi`` loop cycle synced with
  block_build_time_ms configuration parameter.
- Encapsulation of Sumeragi algorithm inside ``sumeragi`` module.
- Mocking module for Iroha Network crate implemented via channels.
- Migration to async-std API.
- Network mock feature.
- Asynchronous related code clean up.
- Performance optimizations in transaction processing loop.
- Generation of key pairs was extracted from Iroha start.
- Docker packaging of Iroha executable.
- Introduce Sumeragi basic scenario.
- Iroha CLI client.
- Drop of iroha after bench group execution.
- Integrate ``sumeragi``.
- Change ``sort_peers`` implementation to rand shuffle seeded with previous block hash.
- Remove Message wrapper in peer module.
- Encapsulate network-related information inside ``torii::uri`` and
  ``iroha_network``.
- Add Peer instruction implemented instead of hardcode handling.
- Peers communication via trusted peers list.
- Encapsulation of network requests handling inside Torii.
- Encapsulation of crypto logic inside crypto module.
- Block sign with timestamp and previous block hash as payload.
- Crypto functions placed on top of the module and work with ursa signer
  encapsulated into Signature.
- Sumeragi initial.
- Validation of transaction instructions on world state view clone
  before commit to store.
- Verify signatures on transaction acceptance.
- Fix bug in Request deserialization.
- Implementation of Iroha signature.
- Blockchain entity was removed to clean up codebase.
- Changes in Transactions API: better creation and work with requests.
- Fix the bug that would create blocks with empty vector of transaction
- Forward pending transactions.
- Fix bug with missing byte in u128 scale encoded TCP packet.
- Attribute macros for methods tracing.
- P2p module.
- Usage of iroha_network in torii and client.
- Add new ISI info.
- Specific type alias for network state.
- Box<dyn Error> replaced with String.
- Network listen stateful.
- Initial validation logic for transactions.
- Iroha_network crate.
- Derive macro for Io, IntoContract and IntoQuery traits.
- Queries implementation for Iroha-client.
- Transformation of Commands into ISI contracts.
- Add proposed design for conditional multisig.
- Migration to Cargo workspaces.
- Modules migration.
- External configuration via environment variables.
- Get and Put requests handling for Torii.
- Github ci correction.
- Cargo-make cleans up blocks after test.
- Introduce ``test_helper_fns`` module with a function to cleanup directory with blocks.
- Implement validation via merkle tree.
- Remove unused derive.
- Propagate async/await and fix unawaited ``wsv::put``.
- Use join from ``futures`` crate.
- Implement parallel store execution: writing to disk and updating WSV are happening in parallel.
- Use references instead of ownership for (de)serialization.
- Code ejection from  files.
- Use ursa::blake2.
- Rule about mod.rs in Contributing guide.
- Hash 32 bytes.
- Blake2 hash.
- Disk accepts references to block.
- Refactoring of commands module and Initial Merkle Tree.
- Refactored modules structure.
- Correct formatting.
- Add doc comments to read_all.
- Implement ``read_all``, reorganize storage tests, and turn tests with async functions into async tests.
- Remove unnecessary mutable capture.
- Review issue, fix clippy.
- Remove dash.
- Add format check.
- Add token.
- Create rust.yml for github actions.
- Introduce disk storage prototype.
- Transfer asset test and functionality.
- Add default initializer to structs.
- Change name of MSTCache struct.
- Add forgotten borrow.
- Initial outline of iroha2 code.
- Initial Kura API.
- Add some basic files and also release the first draft of the
  whitepaper outlining the vision for iroha v2.
- Basic iroha v2 branch.


1.5.0 (2022-04-08)
------------------

CI/CD changes
~~~~~~~~~~~~~
- Remove Jenkinsfile and JenkinsCI.

Features
~~~~~~~~

- Add RocksDB storage implementation for Burrow.
- Introduce traffic optimization with Bloom-filter
- Update ``MST`` module network to be located in ``OS`` module in ``batches_cache``.
- Propose traffic optimization.

Documentation
~~~~~~~~~~~~~

- Fix build. Add DB differences, migration practice,
  healthcheck endpoint, information about iroha-swarm tool.

Other
~~~~~

- Requirement fix for doc build.
- Reduce text, one important TODO.
- Fix 'check if docker image exists' /build all skip_testing.
- /build all skip_testing.
- /build skip_testing; And more docs.
- Add ``.github/_README.md``.
- Remove ``.packer``.
- Remove changes on test parameter.
- Use new parameter to skip test stage.
- Add to workflow.
- Remove repository dispatch.
- Add repository dispatch.
- Add parameter for testers.
- Remove ``proposal_delay`` timeout.


1.4.0 (2022-01-31)
------------------

Features
~~~~~~~~

- Add syncing node state
- Adds metrics for RocksDB
- Add healthcheck interfaces via http, grpc, and metrics.

Fixes
~~~~~

- Fix column families in Iroha v1.4-rc.2
- Add 10-bit bloom filter in Iroha v1.4-rc.1

Documentation
~~~~~~~~~~~~~

- Add zip and pkg-config to list of build deps.
- Update readme: fix broken links to build status, build guide, and so on.
- Fix Config and Docker Metrics.

Other
~~~~~

- Update GHA docker tag.
- Fix Iroha 1 compile errors when compiling with g++11.
- Replace deprecated param ``max_rounds_delay`` with
  ``proposal_creation_timeout``.
  Update sample config file to have not deprecated DB connection params.
