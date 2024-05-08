# Changelog

## [Unreleased]

## [2.0.0-pre-rc.21.3] - 2024-05-08

### Fixed

- replace RawGenesisBlock with RawGenesisBlockFile in schema

## [2.0.0-pre-rc.21.2] - 2024-05-03

### Fixed

- remove serde(flatten) from SetKeyValue/RemoveKeyValue (#4546)

## [2.0.0-pre-rc.21.1] - 2024-05-01

### Fixed

- add RawGenesisBlock to schema (#4538)
- remove nested option on `TransactionEventFilter::block_height` (#4538)

## [2.0.0-pre-rc.21] - 2024-04-19

### Added

- include trigger id in trigger entrypoint (#4391)
- expose event set as bitfields in schema (#4381)
- introduce new `wsv` with granular access (#2664)
- add event filters for `PermissionTokenSchemaUpdate`, `Configuration` and `Executor` events
- introduce snapshot "mode" (#4365)
- allow granting/revoking role's permissions (#4244)
- introduce arbitrary-precision numeric type for assets (remove all other numeric types) (#3660)
- different fuel limit for Executor (#3354)
- integrate pprof profiler (#4250)
- add asset subcommand in client CLI (#4200)
- `Register<AssetDefinition>` permissions (#4049)
- add `chain_id` to prevent replay attacks (#4185)
- add subcommands to edit domain metadata in client CLI (#4175)
- implement store set, remove, get operations in Client CLI (#4163)
- count identical smart contracts for triggers (#4133)
- add subcommand into client CLI to transfer domains (#3974)
- support boxed slices in FFI (#4062)
- git commit SHA to client CLI (#4042)
- proc macro for default validator boilerplate (#3856)
- build progress information to `wasm_builder_cli` (#3237)
- introduced query request builder into Client API (#3124)
- lazy queries inside smart contracts (#3929)
- `fetch_size` query parameter (#3900)
- asset store tranfer instruction (#4258)
- guard against secrets leakage (#3240)
- deduplicate triggers with the same source code (#4419)

### Changed

- bump rust toolchain to nightly-2024-04-18
- send blocks to observing peers (#4387)
- split pipeline events into block and transaction events (#4366)
- rename `[telemetry.dev]` config section to `[dev_telemetry]` (#4377)
- make `Action` and `Filter` non-generic types (#4375)
- improve event filtering API with builder pattern (#3068)
- unify various event filter APIs, introduce a fluent builder API
- rename `FilterBox` into `EventFilterBox`
- rename `TriggeringFilterBox` into `TriggeringEventFilterBox`
- improve filter naming, e.g. `AccountFilter` -> `AccountEventFilter`
- rewrite config according to the configuration RFC (#4239)
- hide internal structure of the versioned structs from the public API (#3887)
- temporarily introduce predictable ordering after too many failed view changes (#4263)
- use concrete key types in `iroha_crypto` (#4181)
- split view changes from normal messages (#4115)
- make `SignedTransaction` immutable (#4162)
- export `iroha_config` through `iroha_client` (#4147)
- export `iroha_crypto` through `iroha_client` (#4149)
- export `data_model` through `iroha_client` (#4081)
- remove `openssl-sys` dependency from `iroha_crypto` and introduce configurable tls backends to `iroha_client` (#3422)
- replace unmaintained EOF `hyperledger/ursa` with in-house solution `iroha_crypto` (#3422)
- optimize executor performance (#4013)
- topology peer update (#3995)

### Fixed

- remove corresponding triggers on `Unregister<Domain>` (#4461)
- remove permissions from roles on entity unregistration (#4242)
- assert that genesis tranasction is signed by genesis pub key (#4253)
- introduce timeout for unresponsive peers in p2p (#4267)
- prevent registering genesis Domain or Account (#4226)
- `MinSize` for `ChaCha20Poly1305` (#4395)
- start console when `tokio-console` is enabled (#4377)
- separate each item with `\n` and recursively create parent directories for `dev-telemetry` file logs
- prevent account registration without signatures (#4212)
- key pair generation is now infallible (#4283)
- stop encoding `X25519` keys as `Ed25519` (#4174)
- do signature validation in `no_std` (#4270)
- calling blocking methods within async context (#4211)
- revoke associated tokens on entity unregistretration (#3962)
- async blocking bug when starting Sumeragi
- fixed `(get|set)_config` 401 HTTP (#4177)
- `musl` archiver name in Docker (#4193)
- smart contract debug print (#4178)
- topology update on restart (#4164)
- registration of new peer (#4142)
- on-chain predictable iteration order (#4130)
- re-architect logger and dynamic configuration (#4100)
- trigger atomicity (#4106)
- query store message ordering issue (#4057)
- set `Content-Type: application/x-parity-scale` for endpoints which reply using SCALE

### Removed

- `logger.tokio_console_address` configuration parameter (#4377)
- `NotificationEvent` (#4377)
- `Value` enum (#4305)
- MST aggregation from iroha (#4229)
- cloning for ISI and query execution in smart contracts (#4182)
- `bridge` and `dex` features (#4152)
- flattened events (#3068)
- expressions (#4089)
- auto-generated config reference
- `IROHA_SKIP_WASM_CHECKS` env variable (#4096)
- `warp` noise in logs (#4097)

### Security

- prevent pub key spoofing in p2p (#4065)
- ensure the `secp256k1` signatures coming out of OpenSSL are normalized (#4155)

## [2.0.0-pre-rc.20] - 2023-10-17

### Added

- make FindTrigger queries return original WASM
- Transfer `Domain` ownership
- `Domain` owner permissions
- Add `owned_by` field to `Domain`
- parse filter as JSON5 in `iroha_client_cli` (#3923)
- Add support for usage of Self type in serde partially tagged enums
- Standardize block API (#3884)
- Implement `Fast` kura init mode
- Add iroha_swarm disclaimer header
- initial support for WSV snapshots

### Fixed

- Fix executor downloading in update_configs.sh (#3990)
- proper rustc in devShell
- Fix burn `Trigger` reprtitions
- Fix transfer `AssetDefinition`
- Fix `RemoveKeyValue` for `Domain`
- Fix double free in wasm tests
- Fix the usage of `Span::join`
- Fix topology mismatch bug (#3903)
- Fix `apply_blocks` and `validate_blocks` benchmark
- Fix wasm memory leak
- `mkdir -r` with store path, not lock path (#3908)
- Don't fail if dir exists in test_env.py
- Fix authentication/authorization docstring (#3876)
- Better error message for query find error
- Add genesis account public key to dev docker compose
- Compare permission token payload as JSON (#3855)
- Fix `irrefutable_let_patterns` in the `#[model]` macro
- Allow genesis to execute any ISI (#3850)
- Fix genesis validation (#3844)
- Fix topology for 3 or less peers
- Correct how tx_amounts histogram is calculated.
- `genesis_transactions_are_validated()` test flakiness
- Default validator generation
- Fix iroha graceful shutdown

### Refactor

- remove unused dependencies (#3992)
- remove optimized WASM from data_model
- bump dependencies (#3981)
- Rename validator to executor (#3976)
- Remove `IsAssetDefinitionOwner` (#3979)
- Include smart contract code into the workspace (#3944)
- Merge API and Telemetry endpoints into a single server
- move expression len out of public API into core (#3949)
- Avoid clone in roles lookup
- Range queries for roles
- Move account roles to `WSV`
- Rename ISI from *Box to *Expr (#3930)
- Remove 'Versioned' prefix from versioned containers (#3913)
- move `commit_topology` into block payload (#3916)
- Migrate iroha_futures_derive to syn 2.0
- Registered with Identifiable in ISI bounds (#3925)
- Add basic generics support to `derive(HasOrigin)`
- Clean up Emitter APIs documentation to make clippy happy
- Add tests for derive(HasOrigin) macro, reduce repetition in derive(IdEqOrdHash), fix error reporting on stable
- Improve naming, simplify repeated .filter_maps & get rid of unnecessary .except in derive(Filter)
- Make PartiallyTaggedSerialize/Deserialize use darling
- Make derive(IdEqOrdHash) use darling, add tests
- Make derive(Filter) use darling
- Update iroha_data_model_derive to use syn 2.0
- Add signature check condition unit tests
- Allow only a fixed set of signature verification conditions
- Generalize ConstBytes into a ConstVec that holds any const sequence
- Use a more efficient representation for bytes values that are not changing
- Store finalized wsv in snapshot
- Add `SnapshotMaker` actor
- document limitation of parsing derives in proc macros
- clean up comments
- extract a common test utility for parsing attributes to lib.rs
- use parse_display & update Attr -> Attrs naming
- allow usage of pattern matching in ffi function args
- reduce repetition in getset attrs parsing
- rename Emitter::into_token_stream into Emitter::finish_token_stream
- Use parse_display to parse getset tokens
- Fix typos and improve error messages
- iroha_ffi_derive: use darling to parse attributes and use syn 2.0
- iroha_ffi_derive: replace proc-macro-error with manyhow
- Simplify kura lock file code
- make all numeric values serialize as string literals
- Split off Kagami (#3841)
- Rewrite `scripts/test-env.sh`
- Differentiate between smart contract and trigger entrypoints
- Elide `.cloned()` in `data_model/src/block.rs`
- Wasm entrypoint payloads
- Make wasm entrypoint names to be public constants
- update `iroha_schema_derive` to use syn 2.0
- store original contract WASM in TriggerSet

## [2.0.0-pre-rc.19] - 2023-08-14

### Added

- hyperledger#3309 Bump `wasmtime` virtual machine for improved
- hyperledger#3665 remove `max_log` query from WASM
- hyperledger#3383 Implement macro to parse a socket addresses at compile time
- hyperledger#2398 Add integration tests for query filters
- Include the actual error message in `InternalError`
- Usage of `nightly-2023-06-25` as the default tool-chain
- hyperledger#3692 Validator migration
- [DSL internship] hyperledger#3688: Implement basic arithmetic as proc macro
- hyperledger#3371 Split validator `entrypoint` to ensure that validators are no longer viewed as smart-contracts
- hyperledger#3651 WSV snapshots, which allow to bring up an Iroha node quickly after a crash
- hyperledger#3752 Replace `MockValidator` with an `Initial` validator that accepts all transactions
- hyperledger#3276 Add temporary instruction called `Log` that logs a specified string to the main log of the Iroha node
- hyperledger#3641 Make the permission token payload human-readable
- hyperledger#3324 Add `iroha_client_cli` related `burn` checks and refactoring
- hyperledger#3781 Validate genesis transactions
- hyperledger#2885 Differentiate between events that can and cannot be used for triggers
- hyperledger#2245 `Nix`-based build of iroha node binary as `AppImage`

### Fixed

- hyperledger#3690 Fix C++ musl docker build which caused `wasmopt` to not compile on some platforms (Alpine Linux)
- hyperledger#3613 Regression which could allow incorrectly signed transactions to be accepted
- Reject incorrect Configuration topology early
- hyperledger#3445 Fix regression and make `POST` on the `/configuration` endpoint work again
- hyperledger#3654 Fix `iroha2` `glibc`-based `Dockerfiles` to be deployed
- hyperledger#3451 Fix `docker` build on Apple silicon macs
- hyperledger#3741 Fix `tempfile` error in `kagami validator`
- hyperledger#3758 Fix regression where individual crates could not be built, but could be built as part of the workspace
- hyperledger#3777 Patch loophole in role registration not being validated
- hyperledger#3805 Fix Iroha not shutting down after receiving `SIGTERM`

### Other

- hyperledger#3648 Include `docker-compose.*.yml` check in the CI processes
- Move instruction `len()` from `iroha_data_model` into `iroha_core`
- hyperledger#3672 Replace `HashMap` with `FxHashMap` in derive macros
- hyperledger#3374 Unify error's doc-comments and `fmt::Display` implementation
- hyperledger#3289 Use Rust 1.70 workspace inheritance throughout project
- hyperledger#3654 Add `Dockerfiles` to build iroha2 on `GNU libc <https://www.gnu.org/software/libc/>`_
- Introduce `syn` 2.0, `manyhow` and `darling` for proc-macros
- hyperledger#3802 Unicode `kagami crypto` seed

## [2.0.0-pre-rc.18]

### Added

- hyperledger#3468: Server-side cursor, which allows for lazily evaluated re-entrant pagination which should have major positive performance implications for query latency
- hyperledger#3624: General purpose permission tokens; specifically
  - Permissions tokens can have any structure
  - Token structure is self-described in the `iroha_schema` and serialised as a JSON string
  - Token value is `SCALE <https://github.com/paritytech/parity-scale-codec>`_-encoded
  - as a consequence of this change permission token naming convention was moved from `snake_case` to `UpeerCamelCase`
- hyperledger#3615 Preserve wsv after validation
- hyperledger#3628 Implement `iroha_wasm_builder` optimisations
- hyperledger#3236 Enhance `iroha_wasm_builder` with cache, and better error messages

### Fixed

- hyperledger#3627 Transaction atomicity now enforced via cloning of the `WorlStateView`
- hyperledger#3195 Extend panic behaviour for when receiving a rejected genesis transaction
- hyperledger#3042 Fix bad request message
- hyperledger#3352 Split up control flow and data message into separate channels
- hyperledger#3543 Improve precision of metrics

## 2.0.0-pre-rc.17

### Added

- hyperledger#3330 Extend `NumericValue` deserialisation
- hyperledger#2622 `u128`/`i128` support in FFI
- hyperledger#3088 Introduce queue throttling, to prevent DoS
- hyperledger#2373 `kagami swarm file` and `kagami swarm dir` command variants for generating `docker-compose` files
- hyperledger#3587 Allow different states in `wasm::Runtime`  and during link-time
- hyperledger#3597 Permission Token Analysis (Iroha side)
- hyperledger#3598 Permission token analysis (WASM side)
- hyperledger#3353 Remove `eyre` from `block.rs` by enumerating error conditions and using strongly-typed errors
- hyperledger#3318 Interleave rejected and accepted transactions in blocks to preserve transaction processing order

### Fixed

- hyperledger#3075 Panic on invalid transaction in the `genesis.json` to prevent invalid transactions from being processed
- hyperledger#3461 Proper handling of default values in default config
- hyperledger#3548 Fix `IntoSchema` transparent attribute
- hyperledger#3552 Fix validator path schema representation
- hyperledger#3546 Fix for time triggers getting stuck
- hyperledger#3162 Forbid 0 height in block streaming requests
- Configuration macro initial test
- hyperledger#3592 Fix for  config files being updated on `release`
- hyperledger#3246 Don't involve `observing peer <https://github.com/hyperledger/iroha/blob/iroha2-dev/docs/source/iroha_2_whitepaper.md#2-system-architecture>`_ without `fault <https://en.wikipedia.org/wiki/Byzantine_fault>`_
- hyperledger#3570 Correctly display client-side string query errors
- hyperledger#3596 `iroha_client_cli` shows blocks/events
- hyperledger#3473 Make `kagami validator` work from outside the  iroha repository root directory

### Other

- hyperledger#3063 Map transaction `hash` to block height in `wsv`
- strongly-typed `HashOf<T>` in `Value`

## [2.0.0-pre-rc.16]

### Added

- hyperledger#2373 `kagami swarm` sub-command for generating `docker-compose.yml`
- hyperledger#3525 Standardize transaction API
- hyperledger#3376 Add Iroha Client CLI `pytest <https://docs.pytest.org/en/7.4.x/>`_ automation framework
- hyperledger#3516 Retain original blob hash in `LoadedExecutable`

### Fixed

- hyperledger#3462 Add `burn` asset command to `client_cli`
- hyperledger#3233 Refactor error types
- hyperledger#3330 Fix regression, by manually implementing `serde::de::Deserialize` for `partially-tagged <https://serde.rs/enum-representations.html>`_ `enums`
- hyperledger#3487 Return missing types into the schema
- hyperledger#3444 Return discriminant into schema
- hyperledger#3496 Fix `SocketAddr` field parsing
- hyperledger#3498 Fix soft-fork detection
- hyperledger#3396 Store block in `kura` before emitting a block committed event

### Other

- hyperledger#2817 Remove interior mutability from `WorldStateView`
- hyperledger#3363 Genesis API refactor
- Refactor existing and supplement with new tests for topology
- Switch from `Codecov <https://about.codecov.io/>`_ to `Coveralls <https://coveralls.io/>`_  for test coverage
- hyperledger#3533 Rename `Bool` to `bool` in schema

## [2.0.0-pre-rc.15]

### Added

- hyperledger#3231 Monolithic validator
- hyperledger#3238 Optimise WASM triggers with pre-loading
- hyperledger#3015 Support for niche optimization in FFI
- hyperledger#2547 Add logo to `AssetDefinition`
- hyperledger#3274 Add to `kagami` a sub-command that generates examples (backported into LTS)
- hyperledger#3415 `Nix <https://nixos.wiki/wiki/Flakes>`_ flake
- hyperledger#3412 Move transaction gossiping to a separate actor
- hyperledger#3435 Introduce `Expression` visitor
- hyperledger#3168 Provide genesis validator as a separate file
- hyperledger#3454 Make LTS the default for most Docker operations and documentation
- hyperledger#3090 Propagate on-chain parameters from blockchain to `sumeragi`

### Fixed

- hyperledger#3330 Fix untagged enum de-serialization with `u128` leaves (backported into RC14)
- hyperledger#2581 reduced noise in logs
- hyperledger#3360 Fix `tx/s` benchmark
- hyperledger#3393 Break communication deadlock loop in `actors`
- hyperledger#3402 Fix `nightly` build
- hyperledger#3411 Properly handle peers simultaneous connection
- hyperledger#3440 Deprecate asset conversions during transfer, instead handled by smart-contracts
- hyperledger#3408: Fix `public_keys_cannot_be_burned_to_nothing` test

### Other

- hyperledger#3362 Migrate to `tokio` actors
- hyperledger#3349 Remove `EvaluateOnHost` from smart contracts
- hyperledger#1786 Add `iroha`-native types for socket addresses
- Disable `wasmtime` cache
- Revert disable cache
- Rename permission validator into validator
- hyperledger#3388 Make `model!` a module-level attribute macro
- hyperledger#3370 Serialize `hash` as hexadecimal string
- Move `maximum_transactions_in_block` from `queue` to `sumeragi` configuration
- Deprecate and remove `AssetDefinitionEntry` type
- Rename `configs/client_cli` into `configs/client`
- Update `MAINTAINERS.md`

## [2.0.0-pre-rc.14]

### Added

- hyperledger#3127 data model `structs` opaque by default
- hyperledger#3122 use `Algorithm` for storing digest function (community contributor)
- hyperledger#3153 `iroha_client_cli` output is machine readable
- hyperledger#3105 Implement `Transfer` for  `AssetDefinition`
- hyperledger#3010 `Transaction` expire pipeline event added
- hyperledger#3144 WASM logging

### Fixed

- hyperledger#3113 revision of unstable network tests
- hyperledger#3129 Fix `Parameter` de/serialisation
- hyperledger#3141 Manually implement `IntoSchema` for `Hash`
- hyperledger#3155 Fix panic hook in tests, preventing deadlock
- hyperledger#3166 Don't view change on idle, improving performance
- hyperledger#2123 Return to PublicKey de/serialization from multihash
- hyperledger#3132 Add NewParameter validator
- hyperledger#3249 Split block hashes into partial and complete versions
- hyperledger#3031 Fix the UI/UX of missing configuration parameters
- hyperledger#3247 Removed fault injection from `sumeragi`.

### Other

- Add missing `#[cfg(debug_assertions)]` to fix spurious failures
- hyperledger#2133 Rewrite topology to be closer the whitepaper
- Remove `iroha_client` dependency on `iroha_core`
- hyperledger#2943 Derive `HasOrigin`
- hyperledger#3226 Extract `iroha_wasm_validator` crate from iroha_wasm
- hyperledger#3232 Share workspace metadata
- hyperledger#3254 Refactor `commit_block()` and `replace_top_block()`
- Use stable default allocator handler
- hyperledger#3183 Rename the `docker-compose.yml` files
- Improved the `Multihash` display format
- hyperledger#3268 Globally unique item identifiers
- New PR template

## [2.0.0-pre-rc.13]

### Added

- hyperledger#2399 Config parameters as ISI.
- hyperledger#3119 Add `dropped_messages` metric.
- hyperledger#3094 Generate network with `n` peers.
- hyperledger#3082 Provide full data in `Created` event.
- hyperledger#3021 Opaque pointer import.
- hyperledger#2794 Reject Fieldless enums with explicit discriminants in FFI.
- hyperledger#2922 Add `Grant<Role>` to default genesis.
- hyperledger#2922 Omit `inner` field in `NewRole` json deserialization.
- hyperledger#2922 Omit `object(_id)` in json deserialization.
- hyperledger#2922 Omit `Id` in json deserialisation.
- hyperledger#2922 Omit `Identifiable` in json deserialization.
- hyperledger#2963 Add `queue_size` to the metrics.
- hyperledger#3027 implement lockfile for Kura.
- hyperledger#2813 Kagami generate default peer config.
- hyperledger#3019 Support JSON5.
- hyperledger#2231 Generate FFI wrapper API.
- hyperledger#2999 Accumulate block signatures.
- hyperledger#2995 Soft fork detection.
- hyperledger#2905 Extend arithmetic operations to support `NumericValue`
- hyperledger#2868 Emit iroha version and commit hash in logs.
- hyperledger#2096 Query for total amount of asset.
- hyperledger#2899 Add multi-instructions subcommand into 'client_cli'
- hyperledger#2247 Remove websocket communication noise.
- hyperledger#2889 Add block streaming support into `iroha_client`
- hyperledger#2508 Add a new client CLI subcommand that accepts wasm.
- hyperledger#2280 Produce permission events when role is granted/revoked.
- hyperledger#2797 Enrich events.
- hyperledger#2725 Reintroduce timeout into `submit_transaction_blocking`
- hyperledger#2712 Config proptests.
- hyperledger#2491 Enum support in FFi.
- hyperledger#2775 Generate different keys in synthetic genesis.
- hyperledger#2627 Config finalisation, proxy entrypoint, kagami docgen.
- hyperledger#2765 Generate synthetic genesis in `kagami`
- hyperledger#2698 Fix unclear error message in `iroha_client`
- hyperledger#2689 Add permission token definition parameters.
- hyperledger#2596 Add Wasm validators.
- hyperledger#2502 Store GIT hash of build.
- hyperledger#2672 Add `ipv4Addr`,  `ipv6Addr` variant and predicates.
- hyperledger#2677 WASM base64 (de-)serialization.
- hyperledger#2626 Implement `Combine` derive, split `config` macros.
- hyperledger#2586 `Builder` and `LoadFromEnv` for proxy structs.
- hyperledger#2611 Derive `TryFromReprC` and `IntoFfi` for generic opaque structs.
- hyperledger#2587 Split `Configurable` into two traits. #2587: Split `Configurable` into two traits
- hyperledger#2488 Add support for trait impls in `ffi_export`
- hyperledger#2553 Add sorting to asset queries.
- hyperledger#2511 Restrict FFI types on wasm.
- hyperledger#2407 Parametrise triggers.
- hyperledger#2536 Introduce `ffi_import` for FFI clients.
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
- hyperledger#2228 Add Unauthorized variant to smartcontracts query error.
- hyperledger#2395 Add panic if genesis cannot be applied.
- hyperledger#2000 Disallow empty names. #2000: Disallow empty names
- hyperledger#2127 Add sanity check to ensure that all data decoded by `parity_scale_codec` is consumed.
- hyperledger#2360 Make `genesis.json` optional again.
- hyperledger#2053 Add tests to all remaining queries in private blockchain.
- hyperledger#2381 Unify `Role` registration.
- hyperledger#2053 Add tests to the asset-related queries in private blockchain.
- hyperledger#2053 Add tests to 'private_blockchain'
- hyperledger#2302 Add 'FindTriggersByDomainId' stub-query.
- hyperledger#1998 Add filters to queries.
- hyperledger#2276 Include current Block hash into BlockHeaderValue.
- hyperledger#2161 Handle id and shared FFI fns.
  - add handle id and implement FFI equivalents of shared traits (Clone, Eq, Ord)
- hyperledger#1638 `configuration` return doc sub-tree.
- hyperledger#2132 Add `endpointN` proc macro.
- hyperledger#2257 Revoke<Role> emits RoleRevoked event.
- hyperledger#2125 Add FindAssetDefinitionById query.
- hyperledger#1926 Add signal handling and graceful shutdown.
- hyperledger#2161 generate FFI functions for `data_model`
- hyperledger#1149 Block file count does not exceed 1000000 per directory.
- hyperledger#1413 Add API version endpoint.
- hyperledger#2103 support querying for blocks and transactions. Add `FindAllTransactions` query
- hyperledger#2186 Add transfer ISI for `BigQuantity` and `Fixed`.
- hyperledger#2056 Add a derive proc macro crate for `AssetValueType` `enum`.
- hyperledger#2100 Add query to find all accounts with asset.
- hyperledger#2179 Optimise trigger execution.
- hyperledger#1883 Remove embedded configuration files.
- hyperledger#2105 handle query errors in client.
- hyperledger#2050 Add role-related queries.
- hyperledger#1572 Specialized permission tokens.
- hyperledger#2121 Check keypair is valid when constructed.
- hyperledger#2099 Add WASM integration test based on Orillion use-case.
- hyperledger#2003 Introduce Parity Scale Decoder tool.
- hyperledger#1952 Add a TPS benchmark as a standard for optimizations.
- hyperledger#2040 Add integration test with transaction execution limit.
- hyperledger#1890 Introduce integration tests based on Orillion use-cases.
- hyperledger#2048 Add toolchain file.
- hyperledger#2100 Add query to find all accounts with asset.
- hyperledger#2179 Optimise trigger execution.
- hyperledger#1883 Remove embedded configuration files.
- hyperledger#2004 Forbid `isize` and `usize` from becoming `IntoSchema`.
- hyperledger#2105 handle query errors in client.
- hyperledger#2050 Add role-related queries.
- hyperledger#1572 Specialized permission tokens.
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

  - Revert "Delete things related to the number of connected peers"

  This reverts commit b228b41dab3c035ce9973b6aa3b35d443c082544.
  - Clarify `Peer` has true public key only after handshake
  - `DisconnectPeer` without tests
  - Implement unregister peer execution
  - Add (un)register peer subcommand to `client_cli`
  - Refuse reconnections from an unregistered peer by its address

  After your peer unregisters and disconnects another peer,
  your network will hear reconnection requests from the peer.
  All you can know at first is the address whose port number is arbitrary.
  So remember the unregistered peer by the part other than the port number
  and refuse reconnection from there
- Add `/status` endpoint to a specific port.

### Fixes

- hyperledger#3129 Fix `Parameter` de/serialization.
- hyperledger#3109 Prevent `sumeragi` sleep after role agnostic message.
- hyperledger#3046 Ensure Iroha can start gracefully on empty
  `./storage`
- hyperledger#2599 Remove nursery lints.
- hyperledger#3087 Collect votes from observing peers after view change.
- hyperledger#3056 Fix `tps-dev` benchmark hanging.
- hyperledger#1170 Implement cloning-wsv-style soft-fork handling.
- hyperledger#2456 Make genesis block unlimited.
- hyperledger#3038 Re-enable multisigs.
- hyperledger#2894 Fix `LOG_FILE_PATH` env variable deserialization.
- hyperledger#2803 Return correct status code for signature errors.
- hyperledger#2963 `Queue` remove transactions correctly.
- hyperledger#0000 Vergen breaking CI.
- hyperledger#2165 Remove toolchain fidget.
- hyperledger#2506 Fix the block validation.
- hyperledger#3013 Properly chain burn validators.
- hyperledger#0000 FFI serialization of references, and `wasm` tests.
- hyperledger#2998 Delete unused Chain code.
- hyperledger#2816 Move responsibility of access to blocks to kura.
- hyperledger#2384 Replace decode with decode_all.
- hyperledger#1967 Replace ValueName with Name.
- hyperledger#2980 Fix block value ffi type.
- hyperledger#2858 Introduce parking_lot::Mutex instead of std.
- hyperledger#2850 Fix deserialization/decoding of `Fixed`
- hyperledger#2923 Return `FindError` when `AssetDefinition` does not
  exist.
- hyperledger#0000 Fix `panic_on_invalid_genesis.sh`
- hyperledger#2880 Close websocket connection properly.
- hyperledger#2880 Fix block streaming.
- hyperledger#2804 `iroha_client_cli` submit transaction blocking.
- hyperledger#2819 Move non-essential members out of WSV.
- Fix expression serialization recursion bug.
- hyperledger#2834 Improve shorthand syntax.
- hyperledger#2379 Add ability to dump new Kura blocks to blocks.txt.
- hyperledger#2758 Add Sorting structure to the schema.
- CI.
- hyperledger#2548 Warn on large genesis file.
- hyperledger#2638 Update `whitepaper` and propagate changes.
- hyperledger#2678 Fix tests on staging branch.
- hyperledger#2678 Fix tests abort on Kura force shutdown.
- hyperledger#2607 Refactor of sumeragi code for more simplicity and
  robustness fixes.
- hyperledger#2561 Reintroduce viewchanges to consensus.
- hyperledger#2560 Add back in block_sync and peer disconnecting.
- hyperledger#2559 Add sumeragi thread shutdown.
- hyperledger#2558 Validate genesis before updating the wsv from kura.
- hyperledger#2465 Reimplement sumeragi node as singlethreaded state
  machine.
- hyperledger#2449 Initial implementation of Sumeragi Restructuring.
- hyperledger#2802 Fix env loading for configuration.
- hyperledger#2787 Notify every listener to shutdown on panic.
- hyperledger#2764 Remove limit on max message size.
- #2571: Better Kura Inspector UX.
- hyperledger#2703 Fix Orillion dev env bugs.
- Fix typo in a doc comment in schema/src.
- hyperledger#2716 Make Duration in Uptime public.
- hyperledger#2700 Export `KURA_BLOCK_STORE_PATH` in docker images.
- hyperledger#0 Remove `/iroha/rust-toolchain.toml` from the builder
  image.
- hyperledger#0 Fix `docker-compose-single.yml`
- hyperledger#2554 Raise error if `secp256k1` seed shorter than 32
  bytes.
- hyperledger#0 Modify `test_env.sh` to allocate storage for each peer.
- hyperledger#2457 Forcibly shut down kura in tests.
- hyperledger#2623 Fix doctest for VariantCount.
- Update an expected error in ui_fail tests.
- Fix incorrect doc comment in permission validators.
- hyperledger#2422 Hide private keys in configuration endpoint response.
- hyperledger#2492: Fix not all triggers being executed that match an event.
- hyperledger#2504 Fix failing tps benchmark.
- hyperledger#2477 Fix bug when permissions from roles weren't counted.
- hyperledger#2416 Fix lints on macOS arm.
- hyperledger#2457 Fix tests flakiness related to shut down on panic.
  #2457: Add shut down on panic configuration
- hyperledger#2473 parse rustc --version instead of RUSTUP_TOOLCHAIN.
- hyperledger#1480 Shut down on panic. #1480: Add panic hook to exit program on panic
- hyperledger#2376 Simplified Kura, no async, two files.
- hyperledger#0000 Docker build failure.
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
  - Fix JSONs according to #1743 `Domain` struct change
- hyperledger#1751 Consensus fixes. #1715: Consensus fixes to handle high load (#1746)
  - View change handling fixes
  - View change proofs made independent of particular transaction hashes
  - Reduced message passing
  - Collect view change votes instead of sending messages right away (improves network resilience)
  - Fully use Actor framework in Sumeragi (schedule messages to self instead of task spawns)
  - Improves fault injection for tests with Sumeragi
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

### Refactor

- Extract functions from sumeragi main loop.
- Refactor `ProofChain` to newtype.
- Remove `Mutex` from `Metrics`
- Remove adt_const_generics nightly feature.
- hyperledger#3039 Introduce waiting buffer for the multisigs.
- Simplify sumeragi.
- hyperledger#3053 Fix clippy lints.
- hyperledger#2506 Add more tests on block validation.
- Remove `BlockStoreTrait` in Kura.
- Update lints for `nightly-2022-12-22`
- hyperledger#3022 Remove `Option` in `transaction_cache`
- hyperledger#3008 Add niche value into `Hash`
- Update lints to 1.65.
- Add small tests to boost coverage.
- Remove dead code from `FaultInjection`
- Call p2p less often from sumeragi.
- hyperledger#2675 Validate item names/ids without allocating Vec.
- hyperledger#2974 Prevent block spoofing without full revalidation.
- more efficient `NonEmpty` in combinators.
- hyperledger#2955 Remove Block from BlockSigned message.
- hyperledger#1868 Prevent validated transactions from being sent
  between peers.
- hyperledger#2458 Implement generic combinator API.
- Add storage folder into gitignore.
- hyperledger#2909 Hardcode ports for nextest.
- hyperledger#2747 Change `LoadFromEnv` API.
- Improve error messages on configuration failure.
- Add extra examples to `genesis.json`
- Remove unused dependencies before `rc9` release.
- Finalise linting on new Sumeragi.
- Extract subprocedures in the main loop.
- hyperledger#2774 Change `kagami` genesis generation mode from flag to
  subcommand.
- hyperledger#2478 Add `SignedTransaction`
- hyperledger#2649 Remove `byteorder` crate from `Kura`
- Rename `DEFAULT_BLOCK_STORE_PATH` from `./blocks` to `./storage`
- hyperledger#2650 Add `ThreadHandler` to shutdown iroha submodules.
- hyperledger#2482 Store `Account` permission tokens in `Wsv`
- Add new lints to 1.62.
- Improve `p2p` error messages.
- hyperledger#2001 `EvaluatesTo` static type checking.
- hyperledger#2052 Make permission tokens registrable with definition.
  #2052: Implement PermissionTokenDefinition
- Ensure all feature combinations work.
- hyperledger#2468 Remove debug supertrait from permission validators.
- hyperledger#2419 Remove explicit `drop`s.
- hyperledger#2253 Add `Registrable` trait to `data_model`
- Implement `Origin` instead of `Identifiable` for the data events.
- hyperledger#2369 Refactor permission validators.
- hyperledger#2307 Make `events_sender` in `WorldStateView` non-optional.
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
- Add wsv reference to queue.
- hyperledger#1210 Split event stream.
  - Move transaction-related functionality to data_model/transaction module
- hyperledger#1725 Remove global state in Torii.
  - Implement `add_state macro_rules` and remove `ToriiState`
- Fix linter error.
- hyperledger#1661 `Cargo.toml` cleanup.
  - Sort out cargo dependencies
- hyperledger#1650 tidy up `data_model`
  - Move World to wsv, fix roles feature, derive IntoSchema for CommittedBlock
- Organisation of `json` files and readme. Update Readme to conform to template.
- 1529: structured logging.
  - Refactor log messages
- `iroha_p2p`
  - Add p2p privatisation.

### Documentation

- Update Iroha Client CLI readme.
- Update tutorial snippets.
- Add 'sort_by_metadata_key' into API spec.
- Update links to documentation.
- Extend tutorial with asset-related docs.
- Remove outdated doc files.
- Review punctuation.
- Move some docs to the tutorial repository.
- Flakyness report for staging branch.
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
- hyperledger#2119 Add guidance on how to hot reload Iroha in a Docker container.
- hyperledger#2181 Review README.
- hyperledger#2113 Document features in Cargo.toml files.
- hyperledger#2177 Clean up gitchangelog output.
- hyperledger#1991 Add readme to Kura inspector.
- hyperledger#2119 Add guidance on how to hot reload Iroha in a Docker container.
- hyperledger#2181 Review README.
- hyperledger#2113 Document features in Cargo.toml files.
- hyperledger#2177 Clean up gitchangelog output.
- hyperledger#1991 Add readme to Kura inspector.
- generate latest changelog.
- Generate changelog.
- Update outdated README files.
- Added missing docs to `api_spec.md`.
- Add wasm README.

### CI/CD changes

- Add five more self-hosted runners.
- Add regular image tag for Soramitsu registry.
- Workaround for libgit2-sys 0.5.0. Revert to 0.4.4.
- Attempt to use arch-based image.
- Update workflows to work on new nightly-only-container.
- Remove binary entrypoints from coverage.
- Switch dev tests to Equinix self-hosted runners.
- hyperledger#2865 Remove usage of tmp file from `scripts/check.sh`
- hyperledger#2781 Add coverage offsets.
- Disable slow integration tests.
- Replace base image with docker cache.
- hyperledger#2781 Add codecov commit parent feature.
- Move jobs to github runners.
- hyperledger#2778 Client config check.
- hyperledger#2732 Add a conditions to update iroha2-base images and add
  PR labels.
- Fix nightly image build.
- Fix `buildx` error with `docker/build-push-action`
- First-aids for non-functioning `tj-actions/changed-files`
- Enable sequential publish of images, after #2662.
- Add harbor registry.
- Auto-label `api-changes` and `config-changes`
- Commit hash in image, toolchain file again, UI isolation,
  schema tracking.
- Make publishing workflows sequential, and complements to #2427.
- hyperledger#2309: Re-enable doc tests in CI.
- hyperledger#2165 Remove codecov install.
- Move to new container to prevent conflicts with current users.
- hyperledger#2158 Upgrade `parity_scale_codec` and other dependencies.
- Fix build.
- hyperledger#2461 Improve iroha2 CI.
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
- Fix Docker publish and iroha2-dev push CI. Move coverage and bench into PR
- Remove unnecessary full Iroha build in CI docker test.

  The Iroha build became useless as it is now done in docker image itself. So the CI only builds the client cli which is used in tests.
- Add support for iroha2 branch in CI pipeline.
  - long tests only ran on PR into iroha2
  - publish docker images only from iroha2
- Additional CI caches.

### Web-Assembly

- Fix return value for QueryBox execution in wasm.
- Produce events while executing wasm smartcontract.

### Version bumps

- Version to pre-rc.13.
- Version to pre-rc.11.
- Version to RC.9.
- Version to RC.8.
- Update versions to RC7.
- Pre-release preparations.
- Update Mold 1.0.
- Bump dependencies.
- Update api_spec.md: fix request/response bodies.
- Update rust version to 1.56.0.
- Update contributing guide.
- Update README.md and `iroha/config.json` to match new API and URL  format.
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

### Schema

- hyperledger#2114 Sorted collections support in schemas.
- hyperledger#2108 Add pagination.
- hyperledger#2114 Sorted collections support in schemas.
- hyperledger#2108 Add pagination.
- Make schema, version and macro no_std compatible.
- Fix signatures in schema.
- Altered  representation of `FixedPoint` in schema.
- Added `RawGenesisBlock` to schema introspection.
- Changed object-models to create schema IR-115.

### Tests

- hyperledger#2544 Tutorial doctests.
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

### Other

- Move parametrization into traits and remove FFI IR types.
- Add support for unions, introduce `non_robust_ref_mut` * implement conststring FFI conversion.
- Improve IdOrdEqHash.
- Remove FilterOpt::BySome from (de-)serialization.
- Make Not transparent.
- Make ContextValue transparent.
- Make Expression::Raw tag optional.
- Add transparency for some instructions.
- Improve (de-)serialization of RoleId.
- Improve (de-)serialization of validator::Id.
- Improve (de-)serialization of PermissionTokenId.
- Improve (de-)serialization of TriggerId.
- Improve (de-)serialization of Asset(-Definition) Ids.
- Improve (de-)serialization of AccountId.
- Improve (de-)serialization of Ipfs and DomainId.
- Remove logger config from client config.
- Add support for transparent structs in FFI.
- Refactor &Option<T> to Option<&T>
- Fix clippy warnings.
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
- hyperledger#1451: Add warning about misconfiguration if `faulty_peers = 0` and `trusted peers count > 1`
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
- Improvements in peer start up:
  - Allows loading genesis public key only from env
  - config, genesis and trusted_peers path can now be specified in cli params
- hyperledger#1134: Integration of Iroha P2P.
- Change query endpoint to POST instead of GET.
- Execute on_start in actor synchronously.
- Migrate to warp.
- Rework commit with broker bug fixes.
- Revert "Introduces multiple broker fixes" commit(9c148c33826067585b5868d297dcdd17c0efe246)
- Introduces multiple broker fixes:
  - Unsubscribe from broker on actor stop
  - Support multiple subscriptions from the same actor type (previously a TODO)
  - Fix a bug where broker always put self as an actor id.
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
- PermissionValidator trait renamed to IsAllowed. and corresponding other name changes
- API spec web socket corrections.
- Removes unnecessary dependencies from docker image.
- Fmt uses Crate import_granularity.
- Introduces Generic Permission Validator.
- Migrate to actor framework.
- Change broker design and add some functionality to actors.
- Configures codecov status checks.
- Uses source based coverage with grcov.
- Fixed multiple build-args format and redeclared ARG for intermediate build containers.
- Introduces SubscriptionAccepted message.
- Remove zero-value assets from accounts after operating upon.
- Fixed docker build arguments format.
- Fixed error message if child block not found.
- Added vendored OpenSSL to build, fixes pkg-config dependency.
- Fix repository name for dockerhub and coverage diff.
- Added clear error text and filename if TrustedPeers could not be loaded.
- Changed text entities to links in docs.
- Fix wrong username secret in Docker publish.
- Fix small typo in whitepaper.
- Allows mod.rs usage for better file structure.
- Move main.rs into separate crate and make permissions for public blockchain.
- Add querying inside client cli.
- Migrate from clap to structopts for cli.
- Limit telemetry to unstable network test.
- Move traits to smartcontracts module.
- Sed -i "s/world_state_view/wsv/g"
- Move smart contracts into separate module.
- Iroha network content length bugfix.
- Adds task local storage for actor id. Useful for deadlock detection.
- Add deadlock detection test to CI
- Add Introspect macro.
- Disambiguates workflow names also formatting corrections
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
- Fix for lockfree WSV:
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
- Added configuration for string length limits and validation of id's for NewAccount, Domain and AssetDefinition IR-1036.
- Substitute log with tracing lib.
- Add ci check for docs and deny dbg macro.
- Introduces grantable permissions.
- Add iroha_config crate.
- Add @alerdenisov as a code owner to approve all incoming merge requests.
- Fix of transaction size check during consensus.
- Revert upgrading of async-std.
- Replace some consts with power of 2 IR-1035.
- Add query to retrieve transaction history IR-1024.
- Add validation of permissions for store and restructure of permission validators.
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
- Infallable pagination. Fix the cases when pagination may unnecessary through errors, not returns empty collections instead.
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
- Removes outdated lines from genesis files. The destination was removed from register ISI in previous commits.
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
- Fix `submit_blocking`.
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
- Add `HttpResponse::ok()`, `HttpResponse::upgrade_required(..)`
- Replacement of old Instruction and Query models with Iroha DSL approach.
- Add BLS signatures support.
- Introduce http server crate.
- Patched libssl.so.1.0.0 with symlink.
- Verifies account signature for transaction.
- Refactor transaction stages.
- Initial domains improvements.
- Implement DSL prototype.
- Improve Torii Benchmarks: disable logging in benchmarks, add success ratio assert.
- Improve test coverage pipeline: replaces `tarpaulin` with `grcov`, publish test coverage report to `codecov.io`.
- Fix RTD theme.
- Delivery artifacts for iroha subprojects.
- Introduce `SignedQueryRequest`.
- Fix a bug with signature verification.
- Rollback transactions support.
- Print generated key-pair as json.
- Support `Secp256k1` key-pair.
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
- OnWorldStateViewChange trigger change: IrohaQuery instead of Instruction.
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
- Decoupling kura from `sumeragi`.
- Check that transactions are not empty before block creation.
- Re-implement Iroha Special Instructions.
- Benchmarks for transactions and blocks transitions.
- Transactions lifecycle and states reworked.
- Blocks lifecycle and states.
- Fix validation bug, `sumeragi` loop cycle synced with block_build_time_ms configuration parameter.
- Encapsulation of Sumeragi algorithm inside `sumeragi` module.
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
- Integrate `sumeragi`.
- Change `sort_peers` implementation to rand shuffle seeded with previous block hash.
- Remove Message wrapper in peer module.
- Encapsulate network-related information inside `torii::uri` and `iroha_network`.
- Add Peer instruction implemented instead of hardcode handling.
- Peers communication via trusted peers list.
- Encapsulation of network requests handling inside Torii.
- Encapsulation of crypto logic inside crypto module.
- Block sign with timestamp and previous block hash as payload.
- Crypto functions placed on top of the module and work with ursa signer encapsulated into Signature.
- Sumeragi initial.
- Validation of transaction instructions on world state view clone before commit to store.
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
- Introduce `test_helper_fns` module with a function to cleanup directory with blocks.
- Implement validation via merkle tree.
- Remove unused derive.
- Propagate async/await and fix unawaited `wsv::put`.
- Use join from `futures` crate.
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
- Implement `read_all`, reorganize storage tests, and turn tests with async functions into async tests.
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
- Add some basic files and also release the first draft of the whitepaper outlining the vision for iroha v2.
- Basic iroha v2 branch.

## [1.5.0] - 2022-04-08

### CI/CD changes
- Remove Jenkinsfile and JenkinsCI.

### Added

- Add RocksDB storage implementation for Burrow.
- Introduce traffic optimization with Bloom-filter
- Update `MST` module network to be located in `OS` module in `batches_cache`.
- Propose traffic optimization.

### Documentation

- Fix build. Add DB differences, migration practice, healthcheck endpoint, information about iroha-swarm tool.

### Other

- Requirement fix for doc build.
- Reduce text, one important TODO.
- Fix 'check if docker image exists' /build all skip_testing.
- /build all skip_testing.
- /build skip_testing; And more docs.
- Add `.github/_README.md`.
- Remove `.packer`.
- Remove changes on test parameter.
- Use new parameter to skip test stage.
- Add to workflow.
- Remove repository dispatch.
- Add repository dispatch.
- Add parameter for testers.
- Remove `proposal_delay` timeout.

## [1.4.0] - 2022-01-31

### Added

- Add syncing node state
- Adds metrics for RocksDB
- Add healthcheck interfaces via http, grpc, and metrics.

### Fixes

- Fix column families in Iroha v1.4-rc.2
- Add 10-bit bloom filter in Iroha v1.4-rc.1

### Documentation

- Add zip and pkg-config to list of build deps.
- Update readme: fix broken links to build status, build guide, and so on.
- Fix Config and Docker Metrics.

### Other

- Update GHA docker tag.
- Fix Iroha 1 compile errors when compiling with g++11.
- Replace deprecated param `max_rounds_delay` with `proposal_creation_timeout`.
- Update sample config file to have not deprecated DB connection params.
