# Repository ownership and dependency map

The [Cargo workspace](../Cargo.toml) declares Rust packages and shared dependency
versions. [The lane manifest](../ci/rust_lanes.toml) is the exhaustive package
inventory: `python3 scripts/rust_ci.py validate` verifies that every workspace
member has exactly one owner lane. The tables below explain the dependency
boundaries and where to make changes.

## Rust ownership

| Owner | Responsibility and dependency boundary |
| --- | --- |
| [`norito`](../crates/norito), `norito_derive` | Canonical binary/JSON codecs and generated codec implementations. Wire layouts are specified in [Norito](../norito.md). |
| `iroha_schema`, `iroha_derive`, `iroha_primitives`, `iroha_crypto` | Schema contracts, derive support, value primitives, identities, hashes, and cryptographic algorithms. Runtime callers depend on these owners. |
| [`iroha_fhe`](../crates/iroha_fhe) | Deterministic exact arithmetic shared by the homomorphic-encryption protocols: word and fixed-modulus arithmetic, NTT, RNS, basis conversion and explicit rounding, with a scalar reference and NEON/AVX2 kernels that return its words. Also owns `bgv`, the exact modular RNS-BGV starting candidate on arbitrary modulus chains (not consumed yet, no profile qualified; costs in [`specs/fhe_bgv_cost_summary.json`](../specs/fhe_bgv_cost_summary.json)). Depends on `zeroize`, `thiserror`, `blake3` and `getrandom`; `iroha_crypto`, `iroha_zkp_halo2` and `iroha_core_privacy` consume its arithmetic. The schemes, wire types and proofs of those consumers stay with their protocols; [`specs/fhe_ownership_inventory.json`](../specs/fhe_ownership_inventory.json) records each owner. |
| [`iroha_model_base`](../crates/iroha_model_base) | Canonical chain labels, domain, topology and peer identities, names, state paths, metadata, parsing errors and their complete validation/codec implementations. Consumers import these owners directly; aggregate, transport and runtime dependencies are forbidden. Further identity/value extraction remains outstanding. |
| [`iroha_service_model`](../crates/iroha_service_model) | State-independent SoraNet policy records and SoraFS defaults. No aggregate ledger, node, SDK, or runtime dependency is allowed. |
| [`iroha_measurement`](../crates/iroha_measurement) | Diagnostic phase tree and resource observation record shared by proof, verification, native and SDK flows, with the harness `scripts/zk_resource_harness.py`. Depends only on `iroha_allocation`, `norito` and the C library; consumers use it as a dev-dependency listed in its consumer inventory. Validation code must never read a measurement. |
| [`iroha_data_model`](../crates/iroha_data_model) | Ledger transactions, blocks, aggregate instructions/events/queries, and built-in model composition. Privacy and most service records still await extraction. |
| [`iroha_torii_shared`](../crates/iroha_torii_shared) | HTTP contracts, canonical route descriptions, configuration projections, and status records. Node-owned code converts runtime state into these records. |
| [`iroha`](../crates/iroha) | Rust SDK. Uses protocol models and shared HTTP contracts without Core, Torii, daemon, IVM, storage-runtime, or telemetry-implementation dependencies. Canonical async context migration remains active. |
| [`iroha_cli_lib`](../crates/iroha_cli), [`iroha_cli`](../crates/iroha_cli/bins) | The parent package provides the `iroha_cli` runtime library for CLI configuration and command flows, including `iroha app sorafs toolkit compile` and archive packing. The nested executable package owns `iroha`, binary tests and compiled build metadata. |
| [`iroha_config`](../crates/iroha_config), `iroha_config_base` | Node configuration versus shared configuration-reading infrastructure. Client code uses the infrastructure directly, without importing node configuration. |
| [`iroha_sumeragi`](../crates/iroha_sumeragi) | Sans-IO Sumeragi consensus core and deterministic simulator ([contract](../specs/sumeragi.md), [lanes](../specs/sumeragi_lanes.md)); depends only on `norito` and `mv`. `iroha_core::sumeragi` drives it in the node. |
| [`iroha_core`](../crates/iroha_core) | Ledger execution, World state, block coordination, consensus, persistence integration, and node invariant enforcement. |
| [`iroha_core_zk`](../crates/iroha_core_zk) | State-free ZK verification and proof relations. Core retains ledger admission and state authority; normal verifier dependencies exclude Core and P2P. |
| [`iroha_core_privacy`](../crates/iroha_core_privacy) | State-free privacy engines, profiles, records and deterministic execution proof relations. Core retains committed-state admission and application. This owner uses IVM and FASTPQ implementations. |
| [`iroha_core_timed_ovn`](../crates/iroha_core_timed_ovn) | Public timed-OVN evidence replay, casting archives and threshold-BLS TLE verification. Core retains state reads, opaque authorizations, signer admission and share custody. |
| [`iroha_torii`](../crates/iroha_torii) | HTTP/stream handlers and routing around Core capabilities. Construction, route decomposition, and runtime service extraction remain in the redesign. |
| [`irohad_lib`](../crates/irohad), [`irohad`](../crates/irohad/bins) | The parent package provides the `irohad` runtime library for configuration, startup, node ownership and shutdown. The nested executable package owns `iroha3d`, Taira and helper launchers, and compiled build metadata. |
| `ivm`, `ivm_abi`, `kotodama_lang` | Deterministic VM execution, its single V1 ABI, and the Kotodama compiler. The Rust SDK excludes these execution packages. Native bridge, JavaScript and Python hosts use IVM; the JavaScript host also compiles Kotodama. |
| [`kotodama_surface`](../crates/kotodama_surface) | Compiler-independent V1 source registry and builtin/policy surface shared by the compiler, artifact admission and VM. Depends on `ivm_abi` and `strum`, without the compiler implementation. |
| [`kotodama_toolchain`](../crates/kotodama_toolchain) | Compiler tools, including `koto` and `dump_program`, and the in-process IVM test runner. Uses the compiler and VM without adding a compiler edge to normal IVM dependencies. |
| `iroha_executor_data_model`, `iroha_executor_data_model_derive` | Typed permission, parameter and custom-instruction records consumed by Core, Torii and SDKs. Core owns their validation natively; custom executors are IVM bytecode. |
| `sorafs_chunker`, `sorafs_manifest`, `sorafs_car`, `sorafs_orchestrator`, `sorafs_node` | Chunking and records, archive primitives, orchestration, and storage runtime ownership. CLI feature-bundle retirement remains outstanding. |
| [`iroha_storage_client`](../crates/iroha_storage_client) | Client-side archive construction, filesystem persistence, orchestrated fetch, and DA workflows above the Rust SDK and storage libraries. Its shipping feature graphs are checked against node-runtime dependencies. |
| [`soranet_incentives`](../crates/soranet_incentives) | Deterministic reward calculation and payout accounting consumed by Core and the orchestrator. It does not depend on either runtime. |
| `soranet_pq`, `tools/soranet-*`, `tools/sora-vpn-*` | SoraNet cryptographic primitives and separately owned relay, handshake, puzzle, and VPN runtimes. |
| [`iroha_musubi_service`](../crates/iroha_musubi_service), `musubi` | Publication service runtime, durable clock and replay journal versus publisher-side package and publication workflows. Shared control records live in `iroha_torii_shared`. |
| `iroha_sccp`, `settlement_router`, `kaigi_zk` | Cross-chain protocol handling, settlement, and capability-specific proof support. |
| `iroha_p2p`, `iroha_logger`, `iroha_telemetry` | Node networking, logging, and runtime metrics. Shared wire records belong below these implementations. |
| [`iroha_panic_hook`](../crates/iroha_panic_hook) | The single process-wide panic-hook suppression state shared by Core, its ZK verifiers, Torii and `irohad`, whose panic hook reads it. Recovery boundaries depend on this crate; copying it would create suppression the hook never observes. |
| `iroha_zkp_halo2`, `fastpq_prover`, `zk_ace_prover` | Proof primitives or execution engines according to their feature-resolved graph. Shipping SDK checks reject node proof-execution features. |
| `iroha_test_network`, [`integration_tests`](../integration_tests), `izanami` | Real network test consumers. CI supplies the daemon and CLI explicitly. Qualified corridors retain their own binary/provenance runners. |
| [`mochi`](../mochi) | Local sandbox application using account-bound SDK streams. The supervisor coordinates generation and peer lifecycles; [genesis artifacts](../mochi/mochi-core/src/supervisor/genesis_material.rs) and [snapshot transactions/recovery](../mochi/mochi-core/src/supervisor/snapshot_restore.rs) have distinct runtime owners. Node orchestration dependencies stay with the application. |
| [`xtask`](../xtask), [`tools`](../tools) | Repository automation, fixture generation, and deployment/service tools. Their manifests declare their actual runtime dependencies. |

The remaining foundational owners and the `iroha_privacy_model` extraction
are tracked in
[the redesign record](../specs/first_release_architecture_redesign.md).
`iroha_storage_client` and `iroha_musubi_service` are implemented boundaries;
`iroha_service_model` still owns only the state-independent policies described
above while the remaining service records await migration.

## SDK and native delivery

| Source | Consumer and runtime ownership |
| --- | --- |
| [`crates/iroha`](../crates/iroha) | Rust SDK; [the operation inventory](sdk_inventory.md) records Torii route authority and pending consumer mapping. |
| [`kotlin/core-jvm`](../kotlin/core-jvm) | Canonical Kotlin/JVM implementation for Kotlin and Java consumers; Norito, models, and client code with JDK 8 API enforcement. |
| [`kotlin/client-android`](../kotlin/client-android) | Android client and keystore integration. Android dependencies stay outside `core-jvm`. |
| [`kotlin/kagemusha-wallet-android`](../kotlin/kagemusha-wallet-android) | Android KAGEMUSHA wallet platform adapter (`sdk.offline.wallet`): payment key, Keystore and backup rules, and the JNI upcall surface for the planned bridge adapter of the Rust `Advance` provider. Native/device qualification is separate from JVM tests. |
| [`kotlin/tools`](../kotlin/tools) | Offline JVM attestation command using the `core-jvm` evidence verifier; owns filesystem/archive input and command output, without Android or SDK publication dependencies. |
| [`IrohaSwift`](../IrohaSwift) | Swift package, tests, and native bridge integration. |
| [`javascript/iroha_js`](../javascript/iroha_js), `iroha_js_host` | JavaScript SDK and Rust native host, with source-bound native provenance. |
| [`python/iroha_python`](../python/iroha_python), `python/iroha_torii_client`, `python/norito_py` | Python high-level SDK/native module, HTTP contracts, and Norito implementation. |
| [`csharp`](../csharp) | .NET SDK, unit/integration tests, and examples. |
| `connect_norito_bridge`, `tools/kotlin-fixture-gen`, `tools/norito_codegen_exporter` | Native exports and shared binding/fixture generators. Native bridge, JavaScript and Python normal graphs use the verifier owners without full Core or P2P; their IVM/configuration/Sumeragi dependencies remain. |

Mirrored Java implementation directories still exist under `java/`; their
capabilities, fixtures, publications, and native exports must migrate before
deletion. New JVM work targets Kotlin. Java-source consumer tests must remain
after consolidation. The Kotlin constraints are in
[`kotlin/CLAUDE.md`](../kotlin/CLAUDE.md).

## Source, evidence, and checks

- [`status.md`](../status.md) summarizes current health and blockers;
  [`roadmap.md`](../roadmap.md) lists remaining outcomes, owners and completion
  criteria. Routine progress and validation results belong in PRs and CI artifacts.
- [`specs`](../specs), [`formal`](../formal), and
  [`fixtures`](../fixtures) own implementation contracts, proofs, and executable
  shared evidence. Public guides belong in the optional sibling `iroha-docs`.
- [`generated-files.toml`](../generated-files.toml) binds checked-in generated
  files to their generator, inputs, and read-only drift checks. Generated build
  output belongs in ignored staging directories.
- [`ci/dependency_budget.json`](../ci/dependency_budget.json) defines dependency
  ownership and forbidden resolved normal/build edges. Run
  `python3 scripts/check_dependency_budget.py --check-boundaries --offline`.
- [Build profiling](profile_build.md) records source-sealed compiler memory.
  A passing compilation alone does not establish a memory or release budget.
- [CI routing](../ci/README.md) separates binary-free tests from consumers of
  exact required binaries. Full release checks include four-validator consensus
  scenarios and actual native/device execution where required.
