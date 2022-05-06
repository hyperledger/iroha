Changelog
=========


(current)
---------

Features
~~~~~~~~
- 2121 Check key-pair is valid when constructed.
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
- 1918 Implement basic authentication for ``client``.
- 1726 Implement a release PR workflow.
- 1815 Make query responses more type-structured.
- 1928 Implement changelog generation using ``gitchangelog``.
- 1902 Add a version of setup_test_env.sh that does not require docker-compose and uses the debug build of Iroha.
- 1619 Introduce event-based triggers.
- 1195 Close a websocket connection cleanly.
- 1606 Add ``ipfs`` link to domain logo in Domain structure.
- 1767 Restrict linear memory usage for WASM smart contracts.
- 1766 Add WASM permission validation.
- 1754 Add Kura inspector CLI.
- 1790 Improve performance by using stack-based vectors.
- 1425 Add WASM helper crate for writing WASM smart contracts.
- 1425 Add limits to WASM execution.
- 1805 Optional terminal colors for panic errors.
- 1749 Add ``no_std`` in ``data_model``
- 1179 Add revoke-permission-or-role instruction.
- 1782 Make ``iroha_crypto`` ``no_std`` compatible.
- 1425 Add WASM runtime.
- 1172 Implement instruction events: split ``iroha_data_model::events`` to files.
- 1734 Validate ``Name`` to exclude whitespaces.
- 1144 Add metadata nesting.
- 1210 Block streaming on the server side: move transaction related functionality to ``data_model/transaction`` module.
- 1331 Implement ``Prometheus`` metrics.
- 1689 Fix feature dependencies by adding cargo bloat.
- 1675 Use type alias instead of a wrapper struct for versioned items.
- 1643 Implement waiting for peers to commit genesis in tests.
- 1678 Add ``try_allocate``: allocation error handling using try_reserve.
- 1216 Add Prometheus endpoint.
- 1238 Update run-time log-level. Create basic ``connection`` entrypoint-based reloading.
- 1652 Check PR Title Format.
- Add the number of connected peers to ``Status``
- Add ``/status`` endpoint to a specific port.

Fixes
~~~~~
- 2081 Fix role registration.
- 1640 Generate config.json and genesis.json.
- 1716 Fix consensus failure with ``f=0`` cases.
- 1845 Allow non-mintable assets to be minted only once.
- 2005 Fix ``Client::listen_for_events()`` not closing WebSocket stream.
- 1623 Create a ``RawGenesisBlockBuilder``.
- 1917 Add ``easy_from_str_impl`` macro.
- 1922 Move ``crypto_cli`` into tools.
- 1969 Make the ``roles`` feature part of the default feature set.
- 2013 Fix CLI arguments.
- 1897 Remove ``usize`` and ``isize`` from serialization.
- 1955 Fix possibility to pass ``:`` inside ``web_login``
- 1943 Add query errors to the schema.
- 1939 Proper features for ``iroha_config_derive``.
- 1908 Fix zero value handling for telemetry analysis script.
- 0000 Make implicitly ignored doc-test explicitly ignored.
- 1865 Use the latest ``smallstr`` to be able to build ``no_std`` WASM smart contracts.
- 1848 Prevent public keys from being burned to nothing.
- 1811 Add tests and checks to dedup trusted peer keys.
- 1821 Add ``IntoSchema`` for ``MerkleTree`` and ``VersionedValidBlock``, fix ``HashOf``
  and ``SignatureOf`` schemas.
- 1819 Remove traceback from error report in validation.
- 1774 Log the exact reason for validation failures.
- 1714 Compare ``PeerId`` only by key.
- 1788 Reduce memory footprint of ``Value``.
- 1804 Fix schema generation for ``HashOf``, ``SignatureOf``, add test to ensure
  no schemas are missing.
- 1802 Improve logging readability.
- 1783 Fix ``torii`` benchmark.
- 1772 Introduce a fix after #1764.
- 1755 Fix JSONs according to #1743 ``Domain`` struct change.
- 1751, 1715 Implement consensus fixes to handle high load.
- 1734 Update genesis to fit the new Domain validation.
- 1742 Improve error messages returned in ``core`` instructions.
- 1404 Add a test to verify that it is possible to both register and mint an asset.
- 1636 Remove ``trusted_peers.json`` and ``structopt``.
- 1706 Update ``max_faults`` to work with updated Topology.
- 1698 Fix public keys, documentation, and error messages.
- 1405, 1593 Fix minting issues.

Refactor
~~~~~~~~
- 2144 Redesign the http workflow on the client side, expose internal API.
- Move to ``clap``.
- Create ``iroha_gen`` binary, consolidate docs and schema_bin.
- 2109 Make ``integration::events::pipeline`` test stable.
- 1982 Encapsulate access to ``iroha_crypto`` structures.
- Add ``AssetDefinition`` builder.
- Remove unnecessary ``&mut`` from the API.
- Encapsulate access to data model structures.
- Refactor ``core``, ``sumeragi``, instance functions, and ``torii``.
- 1903 Move event emission to ``modify_*`` methods.
- Split ``data_model`` lib.rs file.
- Add wsv reference to queue.
- 1210 Split event stream: move transaction related functionality to ``data_model/transaction`` module
- 1725 Remove global state in Torii.
- Fix a linter error.
- 1661 Clean up ``Cargo.toml``.
- 1650 Tidy up ``data_model``: move World to wsv, fix the ``roles`` feature, derive IntoSchema for CommittedBlock.
- Change the organisation of ``json`` files and readme, update Readme to conform to template.
- 1529 Refactor log messages
- Add p2p privatisation.

Documentation
~~~~~~~~~~~~~

- Generate latest changelog.
- Generate changelog.
- Update outdated README files.
- Add missing docs to ``api_spec.md``.
- Add WASM README.
- Update ``Signature`` docs and align arguments of ``verify``.
- Update contributing guide.
- Updated README.md and ``iroha/config.json`` to match new API and URL
  format.
- Update README with information about key generation.
- Update contributing guide.
- Update whitepaper.
- Update network functions description.
- Update whitepaper based on comments.
- Add initial documentation for ``key_pairs``.

CI/CD changes
~~~~~~~~~~~~~
- Add genesis check and update documentation.
- Bump rust, mold, and nightly to 1.60, 1.2.0, and 1.62 respectively.
- Add Load-rs triggers.
- Fix push workflow.
- Add telemetry to default features.
- Add proper tag to push workflow on main.
- Fix failing tests.
- 1657 Update image to rust 1.57, move back to self-hosted runners.
- Switch coverage to use ``lld``.
- Fix CI Dependency.
- Improve CI segmentation.
- Use a fixed Rust version in CI.
- Fix CI for Docker publish and iroha2-dev push.
- Remove unnecessary full Iroha build in CI docker test.
- Add the support for iroha2 branch in CI pipeline.
- Add CI caches.

Web-Assembly
~~~~~~~~~~~~
- Fix return value for QueryBox execution in WASM.
- Produce events while executing WASM smart contract.

Version bumps
~~~~~~~~~~~~~
- Introduce pre-release preparations.
- Update Mold 1.0.
- Bump dependencies.
- Update ``api_spec.md``: fix request/response bodies.
- Link to git hooks instead of copying, use ``--workspace`` vs ``--all`` for cargo subcommands.
- Update rust version to 1.56.0.
- Update docker publish target to ``hyperledger/iroha2``.
- Updates the workflow to match ``main``.
- Update API spec and fix health endpoint.
- Update Rust to 1.54.
- Update ``ursa`` version from 0.3.5 to 0.3.6.
- Update workflows to new runners.
- Update dockerfile for caching and faster CI builds.
- Update ``libssl`` version.
- Update docker files and async-std.
- Fix updated ``clippy``.
- Update asset structure.
- Update out of date lib.
- Update whitepaper and fix linting issues.
- Update the ``cucumber_rust`` lib.
- Update Github Actions workflows.
- Update ``requirements.txt``.
- Update ``common.yaml``.
- Update instruction logic.
- Provide update for WSV, migrate to Scale.
- Update ``.gitignore``.
- Update Kura description in whitepaper.

Schema
~~~~~~
- 2114 Support sorted collections in schemas.
- 2108 Add pagination.
- Make schema, version, and macro ``no_std`` compatible.
- Fix signatures in schema.
- Alter the representation of ``FixedPoint`` in schema.
- Add ``RawGenesisBlock`` to schema introspection.
- Change object-models to create schema IR-115.

Tests
~~~~~
- Add roles integration tests.
- Standardize UI tests format, move derive UI tests to derive crates.
- Fix mock tests, fix futures unordered bug.
- Remove the DSL crate, move tests to ``data_model``.
- Ensure that unstable network tests pass for valid code.
- Add tests to iroha_p2p.
- Capture logs in tests unless a test fails.
- Add polling for tests and fix rarely breaking tests.
- Add the setup for parallel tests.
- Remove root from iroha init and iroha_client tests.
- Fix tests clippy warnings, add checks to CI.
- Fix tx validation errors during benchmark tests.
- 860 Add Iroha Queries and tests.
- Add Iroha custom ISI guide and Cucumber tests.
- Add tests for no-std client.
- Bridge registration changes and tests.
- Add consensus tests with network mock.
- Use temp dir for tests execution.
- Bench tests positive cases.
- Add the initial Merkle Tree functionality with tests.
- Fix tests and World State View initialization.

Other
~~~~~
- Remove ``roles`` feature.
- Share workdir as a volume with dev docker instances.
- Remove Diff associated type in Execute.
- Use custom encoding instead of multival return.
- Remove ``serde_json`` as iroha_crypto dependency.
- Allow only known fields in version attribute.
- Clarify different ports for endpoints.
- Remove Io derive.
- Move back to self-hosted runners.
- Fix new ``clippy`` lints in the code.
- Add actor doc and minor fixes.
- Implement polling a randomly selected peer instead of pushing latest blocks.
- 1492 Add testing for transaction status events for each of 7 peers.
- Use ``FuturesUnordered`` instead of ``join_all``
- Switch to GitHub Runners.
- Use ``VersionedQueryResult`` vs ``QueryResult`` for ``/query`` endpoint.
- Reconnect telemetry.
- Fix dependabot config.
- Add commit-msg git hook to include sign-off.
- Fix the push pipeline.
- Upgrade dependabot.
- Add utility function to get the current system time on queue push.
- 1197 Add DiskIO mock for error injection in Kura tests.
- Add Unregister peer instruction.
- 1493 Add optional nonce to distinguish transactions.
- Remove unnecessary ``sudo``.
- Metadata for domains.
- Fix the random bounces in ``create-docker`` workflow.
- Add ``buildx`` as suggested by the failing pipeline.
- 1454 Fix query error response with specific status code and hints.
- 1186 Introduce sending telemetry to substrate-telemetry.
- 1533 Fix ``VersionedTransaction::from`` modifying creation timestamp,
  change ``trx`` to ``tx`` according to naming convention,
  move keypair and account into shared ``Lazy<>``.
- Fix configure endpoint.
- Add boolean-based asset mintability check.
- Add typed crypto primitives and migrate to typesafe
  cryptography.
- Improve logging: remove code duplication via monomorphic dispatch.
- 1458 For each actor, add mailbox size as a config parameter.
- 1451 Remove ``MAX_FAULTY_PEERS`` parameter.
- Add handler for getting specific block hash.
- Add new query FindTransactionByHash.
- 1185 Rename the crate from ``iroha`` to ``iroha_core``, update the path.
- Fix logs and general improvements.
- 1150 Introduce ``KURA_BLOCKS_PER_STORAGE_FILE`` setting which defaults to 1000
  and defines the number of blocks per each new created datafile.
- Add queue stress test and other minor tests for queue cases.
- Fix log level.
- Add header specification to client library.
- Fix queue panic failure.
- Separate gossip from round.
- Fix queue.
- Fix dockerfile release build.
- Fix https client.
- Speed up ci.
- Remove all ``ursa`` dependencies, except for ``iroha_crypto``.
- Fix overflow when subtracting durations.
- Make fields public in client.
- Push Iroha2 to Dockerhub as nightly.
- Fix http status codes.
- Replace iroha_error with this error, eyre and color-eyre.
- Substitute queue with crossbeam one.
- Remove some useless lint allowances.
- Introduce metadata for asset definitions.
- Removal of arguments from test_network crate.
- Remove unnecessary dependencies.
- Fix ``iroha_client_cli::event``s.
- Remove old network implementation. Closes #1382.
- Add precision for assets. Closes #1169.
- Introduce improvements in peer start up.
- 1134 Integrate Iroha P2P.
- Change query endpoint to POST instead of GET.
- Execute ``on_start`` in actor synchronously.
- Migrate to warp.
- Introduce multiple broker fixes.
- Broker bug - test showcase.
- Add derives for data model.
- Remove ``rwlock`` from ``torii``.
- OOB Query Permission Checks.
- 1272 Eliminate tween-connections in p2p.
- Recursive check for query permissions inside of instructions.
- Schedule stop actors.
- 1165 Add peer status and counts to iroha_p2p
- Check query permissions by account in torii endpoint.
- Remove exposing CPU and memory usage in system metrics.
- Replace JSON with SCALE for WS messages.
- Store proof of view changes.
- Add logging if transaction does not passed signature check condition.
- Fix small issues, added connection listen code.
- Introduce network topology builder.
- Implement P2P network for Iroha.
- Add block size metric.
- Rename ``PermissionValidator`` trait to ``IsAllowed``.
- Correct API spec web socket.
- Remove unnecessary dependencies from docker image.
- Fmt uses Crate import_granularity.
- Introduce Generic Permission Validator to check permissions for queries.
- Migrate to actor framework.
- Change broker design and add some functionality to actors.
- Configure ``codecov`` status checks.
- Use source-based coverage with ``grcov``.
- Fix multiple build-args format and redeclare ARG for intermediate
  build containers.
- Introduce ``SubscriptionAccepted`` message.
- Remove zero-value assets from accounts after operating upon.
- Fix docker build arguments format.
- Fix error message if child block not found.
- Add vendored OpenSSL to build, fixes pkg-config dependency.
- Fix repository name for dockerhub and coverage diff.
- Add clear error text and filename if ``TrustedPeers`` could not be
  loaded.
- Change text entities to links in docs.
- Fix wrong username secret in Docker publish.
- Fix small typo in whitepaper.
- Allow ``mod.rs`` usage for better file structure.
- Move ``main.rs`` into a separate crate and make permissions for public
  blockchain.
- Add querying inside client cli.
- Migrate from ``clap`` to ``structopts`` for CLI.
- Limit telemetry to unstable network test.
- Move traits to smart contracts module.
- Sed -i "s/world_state_view/wsv/g"
- Move smart contracts into separate module.
- Fix an issue with Iroha network content length.
- Add task local storage for actor id, add deadlock detection test to CI.
- Add Introspect macro.
- Disambiguate workflow names.
- Change query API.
- Migrate from ``async-std`` to ``tokio``.
- Add analyze of telemetry to ci.
- Add futures telemetry for iroha.
- Add iroha futures to every async function.
- Add iroha futures for observability of number of polls.
- Add manual deploy and configuration to README.
- Fix ``reporter``.
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
