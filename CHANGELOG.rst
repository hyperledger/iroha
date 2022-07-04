Changelog
=========


2.0.0-pre.rc.6-lts
---------

Features
~~~~~~~~
- 2395 Add panic if genesis cannot be applied.
- 2000 Disallow empty names. #2000: Disallow empty names
- 2127 Add sanity check to ensure that all data decoded by
  `parity_scale_codec` is consumed.
- 2360 Make `genesis.json` optional again.
- 2053 Add tests to all remaining queries in private blockchain.
- 2381 Unify `Role` registration.
- 2053 Add tests to the asset-related queries in private blockchain.
- 2053 Add tests to 'private_blockchain'
- 2302 Add 'FindTriggersByDomainId' stub-query.
- 1998 Add filters to queries.
- 2276 Include current Block hash into BlockHeaderValue.
- 2161 Handle id and shared FFI fns.
  * add handle id and implement FFI equivalents of shared traits - Clone,Eq,Ord
- 1638 `configuration` return doc subtree.
- 2132 Add `endpointN` proc macro.
- 2257 Revoke<Role> emits RoleRevoked event.
- 2125 Add FindAssetDefinitionById query.
- 1926 Add signal handling and graceful shutdown.
- 2161 generate FFI functions for `data_model`
- 1149 Block file count does not exceed 1000000 per directory.
- 1413 Add API version endpoint.
- 2103 support querying for blocks and transactions. add FindAllTransactions query
- 2186 Add transfer ISI for `BigQuantity` and `Fixed`.
- 2056 Add a derive proc macro crate for AssetValueType enum.
- 2100 Add query to find all accounts with asset.
- 2179 Optimise trigger execution.
- 1883 Remove embedded configuration files.
- 2004 Forbid `isize` and `usize` from becoming `IntoSchema`.
- 2105 handle query errors in client.
- 2050 Add role-related queries.
- #1572: Specialized permission tokens.
- 2121 Check keypair is valid when constructed.
- 2099 Add WASM integration test based on Orillion use-case.
- 2003 Introduce Parity Scale Decoder tool.
- 1952 Add a TPS benchmark as a standard for optimizations.
- 2040 Add integration test with transaction execution limit.
- 1890 Introduce integration tests based on Orillion use-cases.
- 2048 Add toolchain file.
- 2100 Add query to find all accounts with asset.
- 2179 Optimise trigger execution.
- 1883 Remove embedded configuration files.
- 2004 Forbid `isize` and `usize` from becoming `IntoSchema`.
- 2105 handle query errors in client.
- 2050 Add role-related queries.
- #1572: Specialized permission tokens.
- 2121 Check keypair is valid when constructed.
- 2099 Add WASM integration test based on Orillion use-case.
- 2003 Introduce Parity Scale Decoder tool.
- 1952 Add a TPS benchmark as a standard for optimizations.
- 2040 Add integration test with transaction execution limit.
- 1890 Introduce integration tests based on Orillion use-cases.
- 2048 Add toolchain file.
- 2037 Introduce Pre-commit Triggers.
- 1621 Introduce By Call Triggers.
- 1970 Add optional schema endpoint.
- 1620 Introduce time based triggers.
- 1918 Implement basic authentication for `client`
- 1726 Implement a release PR workflow.
- 1815 Make query responses more type-structured.
- 1928 implement changelog generation using `gitchangelog`
- 1902 Bare metal 4-peer setup script.
- 1619 Introduce event-based triggers.
- 1195 Close a websocket connection cleanly.
- 1606 Add ipfs link to domain logo in Domain structure.
- 1767 restrict linear memory usage for wasm smartcontracts.
- 1766 Wasm permission validation.

  * custom decode for SignaturesOf
- 1754 Add Kura inspector CLI.

  * Define the interface
- 1790 Improve performance by using stack-based vectors.
- 1425 Wasm helper crate.

  * add helper crate for writing wasm smartcontracts
- 1425 add limits to wasm execution.
- 1805 Optional terminal colors for panic errors.
- 1749 `no_std` in `data_model`
- 1179 Add revoke-permission-or-role instruction.
- 1782 make iroha_crypto no_std compatible.
- 1425 add wasm runtime.

  * add wasm runtime
- 1172 Implement instruction events.

  * Split `iroha_data_model::events` to files
- 1734 Validate `Name` to exclude whitespaces.

  * Unify metadata key to `Name`
- 1144 Add metadata nesting.

  * Added nested metadata.
- #1210 Block streaming - server side.

  * move transaction related functionality to data_model/transaction module
- 1331 Implement more `Prometheus` metrics.

  * Initial implementation of some metrics.
- 1689 Fix feature dependencies. #1261: Add cargo bloat.
- 1675 use type instead of wrapper struct for versioned items.

  * use type instead of wrapper struct for inner versioned items
- 1643 Wait for peers to commit genesis in tests.
- 1678 `try_allocate`

  * Added allocation error handling using try_reserve.
- 1216 Add Prometheus endpoint.  #1216 - initial implementation of metrics endpoint.
- 1238 Run-time log-level updates. Created basic `connection` entrypoint-based reloading.
- 1652 PR Title Formatting.
- Add the number of connected peers to `Status`

  * Revert "Delete things related to the number of connected peers"

  This reverts commit b228b41dab3c035ce9973b6aa3b35d443c082544.



  * Clarify `Peer` has true public key only after handshake



  * `DisconnectPeer` without tests



  * Implement unregister peer execution



  * Add (un)register peer subcommand to `client_cli`



  * Refuse reconnections from an unregistered peer by its address

  After your peer unregisters and disconnects another peer,
  your network will hear reconnection requests from the peer.
  All you can know at first is the address whose port number is arbitrary.
  So remember the unregistered peer by the part other than the port number
  and refuse reconnection from there
- Add `/status` endpoint to a specific port.

  * Add `/status` endpoint to a specific port

Fixes
~~~~~
- 0000 Docker build failure.
- 1649 remove `spawn` from `do_send`
- 2128 Fix `MerkleTree` construction and iteration.
- 2137 Prepare tests for multiprocess context.
- 2227 Implement Register and Unregister for Asset.
- 2081 Fix role granting bug.
- 2358 Add release with debug profile.
- 2294 Add flamegraph generation to oneshot.rs.
- 2202 Fix total field in query response.
- 2081 Fix the test case to grant the role.
- 2017 Fix role unregistration.
- 2303 Fix docker-compose' peers doesn't get gracefully shut down.

- 2295 Fix unregister trigger bug.
- 2282 improve FFI derives from getset implementation.
- 1149 Remove nocheckin code.
- 2232 Make Iroha print meaningful message when genesis has too many
  isi.
- 2170 Fixes build in docker container on M1 machines.
- 2215 Make nightly-2022-04-20 optional for `cargo build`
- 1990 Enable peer startup via env vars in the absence of config.json.

- 2081 Fix role registration.
- 1640 Generate config.json and genesis.json.
- 1716 Fix consensus failure with f=0 cases.
- 1845 Non-mintable assets can be minted once only.
- 2005 Fix `Client::listen_for_events()` not closing WebSocket stream.

- 1623 Create a RawGenesisBlockBuilder.
- 1917 Add easy_from_str_impl macro.
- 1990 Enable peer startup via env vars in the absence of config.json.

- 2081 Fix role registration.
- 1640 Generate config.json and genesis.json.
- 1716 Fix consensus failure with f=0 cases.
- 1845 Non-mintable assets can be minted once only.
- 2005 Fix `Client::listen_for_events()` not closing WebSocket stream.

- 1623 Create a RawGenesisBlockBuilder.
- 1917 Add easy_from_str_impl macro.
- 1922 Move crypto_cli into tools.
- 1969 Make the `roles` feature part of the default feature set.

- 2013 Hotfix CLI args.
- 1897 Remove usize/isize from serialization.
- 1955 Fix possibility to pass `:` inside `web_login`
- 1943 Add query errors to the schema.
- 1939 Proper features for `iroha_config_derive`.
- 1908 fix zero value handling for telemetry analysis script.
- 0000 Make implicitly ignored doc-test explicitly ignored. Fix typo.

- 1865 use latest smallstr to be able to build no_std wasm
  smartcontracts.
- 1848 Prevent public keys from being burned to nothing.
- 1811 added tests and checks to dedup trusted peer keys.
- 1821 add IntoSchema for MerkleTree and VersionedValidBlock, fix HashOf
  and SignatureOf schemas.
- 1819 Remove traceback from error report in validation.
- 1774 log exact reason for validation failures.
- 1714 Compare PeerId only by key.
- 1788 Reduce memory footprint of `Value`.
- 1804 fix schema generation for HashOf, SignatureOf, add test to ensure
  no schemas are missing.
- 1802 Logging readability improvements.

  - events log moved to trace level
  - ctx removed from log capture
  - terminal colors are made optional (for better log output to files)
- 1783 Fixed torii benchmark.
- 1772 Fix after #1764.
- 1755 Minor fixes for #1743, #1725.

  * Fix JSONs according to #1743 `Domain` struct change
- 1751 Consensus fixes. #1715: Consensus fixes to handle high load (#1746)

  * View change handling fixes

  - View change proofs made independent of particular transaction hashes
  - Reduced message passing
  - Collect view change votes instead of sending messages right away (improves network resilience)
  - Fully use Actor framework in Sumeragi (schedule messages to self instead of task spawns)



  * Improves fault injection for tests with Sumeragi

  - Brings testing code closer to production code
  - Removes overcomplicated wrappers
  - Allows Sumeragi use actor Context in test code
- 1734 Update genesis to fit the new Domain validation.
- 1742 Concrete errors returned in `core` instructions.
- 1404 Verify fixed.
- 1636 Remove `trusted_peers.json` and `structopt` #1636: Remove `trusted_peers.json`.
- 1706 Update `max_faults` with Topology update.

  * Update `max_faults` with Topology update
- 1698 Fixed public keys, documentation and error messages.
- Minting issues (1593 and 1405) issue 1405

Refactor
~~~~~~~~
- 1985 Reduce size of `Name` struct.
- Add more const fn.
- Make integration tests use default_permissions()
- Add permission token wrappers in private_blockchain.
- 2292 Remove `WorldTrait`, remove generics from `IsAllowedBoxed`

- 2204 Make Asset-related operations generic.
- 2233 Replace `impl` with `derive` for `Display` and `Debug`.

- Identifiable structure improvement.
- 2323 Enhance kura init error message.
- 2238 Add peer builder for tests.
- 2011 More descriptive config params.
- 1896 Simplify `produce_event` implementation.
- Refactor around `QueryError`
- Move `TriggerSet` to `data_model`
- 2145 refactor client's `WebSocket` side, extract pure data logic.


  * feat: impl ws transport-agnostic design
- Remove `ValueMarker` trait.
- ` with explicit `trace` directives.
- 2149 Expose `Mintable` and `MintabilityError` in `prelude`
- 2144 redesign client's http workflow, expose internal api.
- Move to `clap`.
- Create `iroha_gen` binary, consolidating docs, schema_bin.
- 2109 Make `integration::events::pipeline` test stable.
- 1982 encapsulate access to `iroha_crypto` structures.
- Add `AssetDefinition` builder.
- Remove unnecessary `&mut` from the API.
- Encapsulate access to data model structures.
- 2144 redesign client's http workflow, expose internal api.
- Move to `clap`.
- Create `iroha_gen` binary, consolidating docs, schema_bin.
- 2109 Make `integration::events::pipeline` test stable.
- 1982 encapsulate access to `iroha_crypto` structures.
- Add `AssetDefinition` builder.
- Remove unnecessary `&mut` from the API.
- Encapsulate access to data model structures.
- Core, `sumeragi`, instance functions, `torii`
- 1903 move event emission to `modify_*` methods.
- Split `data_model` lib.rs file.
- Add wsv reference to quueue.
- 1210 Split event stream.

  * move transaction related functionality to data_model/transaction module
- 1725 Remove global state in Torii.

  * implement add_state macro_rules and remove `ToriiState`
- Fix linter error.
- 1661 `Cargo.toml` cleanup.

  * sort out cargo dependencies
- 1650 tidy up `data_model`

  * move World to wsv, fix roles feature, derive IntoSchema for CommittedBlock
- Organisation of `json` files and readme.  Updated Readme to conform to template.
- 1529: structured logging.

  * refactor log messages
- `iroha_p2p`

  * Added p2p privatisation.

Documentation
~~~~~~~~~~~~~
- 2344 Generate CHANGELOG for 2.0.0-pre-rc.5-lts.
- Add links to the tutorial.
- Update information on git hooks.
- Flakyness test writeup.
- 2193 Update Iroha client documentation.
- 2193 Update Iroha CLI documentation.
- 2193 Update README for macro crate.
- 2193 Update README for wasm crate.
- 2193 Update Parity Scale Decoder Tool documentation.
- 2193 Update Kagami documentation.
- 2193 Update benchmarks documentation.
- 2192 Review contributing guidelines.
- Fix broken in-code references.
- 1280 Document Iroha metrics.
- 2119 Add guidance on how to hot reload Iroha in a Docker container.

- 2181 Review README.
- 2113 Document features in Cargo.toml files.
- 2177 Clean up gitchangelog output.
- 1991 Add readme to Kura inspector.
- 2119 Add guidance on how to hot reload Iroha in a Docker container.

- 2181 Review README.
- 2113 Document features in Cargo.toml files.
- 2177 Clean up gitchangelog output.
- 1991 Add readme to Kura inspector.
- Generate latest changelog.
- Generate changelog.
- Update outdated README files.
- Added missing docs to `api_spec.md`.
- Add wasm README.

  * add wasm README
- ..

CI/CD changes
~~~~~~~~~~~~~
- Add `cargo deny` file.
- Add `iroha2-lts` branch with workflow copied from `iroha2`
- 2393 Bump the version of the Docker base image.
- 1658 Add documentation check.
- Version bump of crates and remove unused dependencies.
- Remove unnecessary coverage reporting.
- 2222 Split tests by whether it involves coverage or not.
- 2153 Fix #2154.
- Version bump all of the crates.
- Fix deploy pipeline.
- 2153 Fix coverage.
- Add genesis check and update documentation.
- Bump rust, mold and nightly to 1.60, 1.2.0 and 1.62 respectively.

- Load-rs triggers.
- 2153 Fix #2154.
- Version bump all of the crates.
- Fix deploy pipeline.
- 2153 Fix coverage.
- Add genesis check and update documentation.
- Bump rust, mold and nightly to 1.60, 1.2.0 and 1.62respectively.

- Load-rs triggers.
- Load-rs:release workflow triggers.
- Fix push workflow.
- Add telemetry to default features.
- Add proper tag to push workflow on main.
- Fix failing tests.
- 1657 Update image to rust 1.57. #1630: Move back to self-hosted runners.
- CI improvements.

  * Switched coverage to use `lld`.
- CI Dependency FIx.

  * Master rebase
- CI segmentation improvements.

  * Master rebase
- Uses a fixed Rust version in CI.
- Fixes Docker publish and iroha2-dev push CI.

  Also moves coverage and bench into PR
- Removes unnecessary full Iroha build in CI docker test.

  The Iroha build became useless as it is now done in docker image itself. So the CI only builds the client cli which is used in tests.
- Adds supports for iroha2 branch in CI pipeline.

  - long tests only ran on PR into iroha2
  - publish docker images only from iroha2
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
- Updated README.md and `iroha/config.json` to match new API and URL
  format.
- Update docker publish target to hyperledger/iroha2 #1453.

  Fix some workflows #
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
- 2114 Sorted collections support in schemas.
- 2108 Add pagination.
- 2114 Sorted collections support in schemas.
- 2108 Add pagination.
- Make schema, version and macro no_std compatible.
- Fix signatures in schema.
- Altered  representation of `FixedPoint` in schema.
- Added `RawGenesisBlock` to schema introspection.
- Changed object-models to create schema IR-115.

Tests
~~~~~
- 2272 Add tests for 'FindAssetDefinitionById' query.
- Add roles integration tests.
- Add roles integration tests.
- Standardize ui tests format, move derive ui tests to derive crates.

- Fix mock tests - futures unordered bug.
- Removed the DSL crate & moved tests to `data_model`
- Ensure that unstable network tests pass for valid code.
- Added tests to iroha_p2p.
- Captures logs in tests unless test fails.
- Add polling for tests and fix rarely breaking tests.
- Tests parallel setup.
- Remove root from iroha init and iroha_client tests.
- Fix tests clippy warnings and adds checks to ci.
- Fixes tx validation errors during benchmark tests.

  Also fixes a bug with tarpauline segfault.
- IR-860: Iroha Queries and tests.
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
- Fix clippy warnings.
- Add test.
- Add more details in `Find` error description.
- Fix `PartialOrd` and `Ord` implementations.
- Replace strings with objects.
- Use `rustfmt` instead of `cargo fmt`
- Remove `roles` feature.
- Replace strings with objects.
- Use `rustfmt` instead of `cargo fmt`
- Remove `roles` feature.
- Share workdir as a volume with dev docker instances.
- Remove Diff associated type in Execute.
- Use custom encoding instead of multival return.
- Remove serde_json as iroha_crypto dependency.
- Allow only known fields in version attribute.
- Clarify different ports for endpoints.
- Remove Io derive.
- Initial documentation of key_pairs.
- Move back to self-hosted runners.
- Fix new clippy lints in the code.
- Remove i1i1 from maintainers.
- Add actor doc and minor fixes.
- Poll instead of pushing latest blocks.

  * poll instead of pushing latest blocks
- Transaction status events tested for each of 7 peers.
- `FuturesUnordered` instead of `join_all`

  * use FuturesUnordered instead of join_all
- Switch to GitHub Runners.
- Use VersionedQueryResult vs QueryResult for /query endpoint.

  * return versioned query response for /query endpoint
- Reconnect telemetry.
- Fix dependabot config.
- Add commit-msg git hook to include signoff.

  * add commit-msg git hook to ensure signoff is included in commit msg
- Fix the push pipeline.
- Upgrade dependabot.
- Detect future timestamp on queue push.

  * Add utility function to get the current system time
- GaroRobe/issue1197.

  * Added DiskIO mock for error injection in Kura tests.
- Add Unregister peer instruction.

  * Master rebase
- Add optional nonce to distinguish transactions. Close #1493.
- Removed unnecessary `sudo`.
- Metadata for domains.
- Fix the random bounces in `create-docker` workflow.

  * Should fix the random bounces in `create-docker` workflow.
- Added `buildx` as suggested by the failing pipeline.
- Fix query error response with specific status code and hints. Close
  #1454.

  * Fix query error response with specific status code and hints. Close #1454
- Sending telemetry.
- GaroRobe/issue1533.

  * Fixed VersionedTransaction::from modifying creation timestamp.
  * Changed trx to tx, according to naming convention
  * Moved keypair and account into shared Lazy<>
- Fixup configure endpoint.
- Added boolean-based asset mintability check.

  * Added boolean-based asset mintability check.
- Addition of typed crypto primitives and migration to typesafe
  cryptography.
- Logging improvements.

  * Removed code duplication via monomorphic dispatch.
- GaroRobe/issue1458.

  * For each Actor added mailbox size
  as a config parmeter.
- GaroRobe/issue1451.

  Removed MAX_FAULTY_PEERS parameter.
  Now max_faulty_peers() is a SumeragiConfiguration method.
  Calculated as (f-1)/3, where f is trusted peers count.
- Add handler for getting specific block hash.
- Added new query FindTransactionByHash.
- Change crates name and path. Close #1185.

  * Rename the library: `iroha` to `iroha_core`
- Fix logs and general improvements.
- GaroRobe/issue1150.

  * Implemented feature for data files to store configurable number of blocks.
  * Proper async stream-style deserialization.
  * Added BlockStoreError for better error markup and 3 error-specific tests:
  1. Inconsequent write error
  2. Inconsequent read error
  3. Corrupted datafile error
  * Changed frame size type to u64.
  Temporarily limited buffer size for frame with 500Kb constant.
- Queue stress test.

  - Queue stress test
  - Some other minor tests added for queue cases
  - Queue test fixes
  - Fixes in the queue behavior due to improper rebase
- Log level fix.
- Add header specification to client library.
- Queue panic failure fix.
- Gossip separated from round.

  Fixes bug when sometimes leader wouldn't propagate MST transactions
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
- Remove old network implementation. Closes #1382.
- Added precision for assets. Closes #1169.
- Improvements in peer start up.

  - Allows loading genesis public key only from env
  - config, genesis and trusted_peers path can now be specified in cli params
- Integration of Iroha P2P. Closes #1134.
- Change query endpoint to POST instead of GET.
- Execute on_start in actor synchronously.
- Migrate to warp.
- Rework commit with broker bug fixes.
- Revert "Introduces multiple broker fixes"

  This reverts commit 9c148c33826067585b5868d297dcdd17c0efe246.
- Introduces multiple broker fixes.

  1. Unsubscribe from broker on actor stop
  2. Support multiple subscriptions from the same actor type (previously a TODO)
  3. Fixes a bug where broker always put self as an actor id.
- Broker bug - test showcase.
- Add derives for data model.
- Remove rwlock from torii.
- OOB Query Permission Checks.
- Implementation of peer counts, closes #1272.
- Recursive check for query permissions inside of instructions.
- Schedule stop actors.
- Implementation of peer counts, closes #1165.
- Check query permissions by account in torii endpoint.
- Removed exposing CPU and memory usage in system metrics.
- Replace JSON with SCALE for WS messages.
- Store proof of view changes.

  - Store proofs
  - Use these proofs in BlockCreated to be up to date
  - Refactor view change handling logic
- Added logging if transaction does not passed sugnature check condition
  IR-1168.
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

  This will enable us to check permissions for query, with the use of already written combinators.
- Migrate to actor framework.
- Change broker design and add some functionality to actors.
- Configures codecov status checks.

  - The project status check will fail if the relative decrease in coverage is more than 5%
  - Check for percentage of new code coverage disabled
- Uses source based coverage with grcov.
- Fixed multiple build-args format and redeclared ARG for intermediate
  build containers.
- Introduces SubscriptionAccepted message.

  The message means that all event connection is initialized and will be supplying events starting from the next one.
- Remove zero-value assets from accounts after operating upon.

- Fixed docker build arguments format.
- Fixed error message if child block not found.
- Added vendored OpenSSL to build, fixes pkg-config dependency.

- Fixes repository name for dockerhub and coverage diff.
- Added clear error text and filename if TrustedPeers could not be
  loaded.
- Changed text entities to links in docs.
- Fixes wrong username secret in Docker publish.
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
- Fix lock-free WSV.
- Add telemetry subscriber.
- Add queries for roles and permissions.
- Move blocks from kura to wsv.
- Change to lock-free data structures inside wsv.
- Fix network timeout .
- Fix health endpoint.
- Introduce Roles.
- Add push docker images from dev branch.
- Add more aggressive linting and remove panics from code.
- Rework of Execute trait for instructions.
- Remove old code from iroha_config.
- IR-1060 Add Grant checks for all the existing permissions.
- Fix ulimit and timeout for iroha_network.
- Ci timeout test fix.
- Remove all assets when their definition was removed.
- Fix wsv panic at adding asset.
- Remove Arc and Rwlock for channels.
- Fix Iroha network.
- Permission Validators use references in checks.
- Grant Instruction.
- Add configuration for string length limits and validation of id's
  for NewAccount, Domain and AssetDefinition IR-1036.
- Substitute log with tracing lib.
- Add ci check for docs and deny dbg macro.
- Introduce grantable permissions.
- Add iroha_config crate.
- Fix of transaction size check during consensus.
- Revert upgrading of async-std.
- Replace some consts with power of 2 IR-1035.
- Add query to retrieve transaction history IR-1024.
- Add validation of permissions for store and restructure of permission
  validators.
- Add NewAccount for account registration.
- Add types for asset definition.
- Introduce configurable metadata limits.
- Introduce transaction metadata.
- Add expressions inside queries.
- Add lints.toml and fix warnings.
- Separate trusted_peers from config.json.
- Fix typo in URL to Iroha 2 community in Telegram.
- Fix clippy warnings.
- Introduce key-value metadata support for Account.
- Add versioning of blocks.
- Fixup ci linting repetitions.
- Add mul,div,mod,raise_to expressions.
- Add into_v* for versioning.
- Substitute Error::msg with error macro.
- Rewrite iroha_http_server and rework torii errors.
- Upgrades SCALE version to 2.
- Whitepaper versioning description.
- Fix the cases when pagination may unnecessary through errors, not returns empty collections instead.
- Add derive(Error) for enums.
- Fix nightly version.
- Add ``iroha_error`` crate.
- Versioned messages.
- Introduce container versioning primitives.
- Fix benchmarks.
- Add pagination.
- Add ``varint`` encoding decoding.
- Change query timestamp to u128.
- Add RejectionReason enum for pipeline events.
- Remove outdated lines from genesis files.
- Simplify register and unregister ISIs.
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
- Fixes a bug with signature verification.
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
- OnWorldStateViewChange trigger change - IrohaQuery instead of
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
- Changes in Transactions API - better creation and work with requests.
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
