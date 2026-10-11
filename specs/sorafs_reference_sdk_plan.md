---
title: SoraFS Reference SDK & Validator
summary: SF-11 implementation status for reference validators, CLI and FFI surfaces, release packaging, and remaining live-release evidence.
---

# SoraFS Reference SDK & Validator

## Goals & Scope
- Ship a Rust reference crate and CLI that sign, verify, and enforce SoraFS governance policies for adverts, replication orders, PoR/PDP/PoTR artefacts, repairs, and governance envelopes.
- Provide deterministic machine-readable outcomes so operators, auditors, and CI systems can gate deployments without bespoke tooling.
- Expose bindings and artefacts other language teams can reuse (via FFI or generated code) while keeping Norito as the only canonical wire format.

## Status
The local SF-11 reference validator and SDK foundations are implemented for
provider adverts, admission envelopes, admission renewals/revocations,
replication orders, signed replication orders, orderbook payloads, PoR
challenge/proof pairs, PDP commitments/challenges/proofs, PoTR receipts, repair payloads, fixture bundles,
governance log nodes, governance DAG blocks and signed-head chains, runtime
signing helpers, C FFI validation, cookbook fixtures, and manifest/CAR replay.
Remaining SF-11 work is native qualification, release evidence, and SDK
distribution: clean five-target ABI-29 rebuilds, skip-free parity replay,
published archives and bindings, signed manifests, and live operator smokes.
The checked-in, test-only signed and sealed cross-domain fixture inventory binds
85 payload artifacts, 35 `ValidationOutcomeV1` outcomes, and 41 negative
payload vectors across twelve exact parity profiles. All eight generated
`CancelAssetLock` positive/negative files are checked in under
`fixtures/sorafs_manifest/appeal_finance/`, are mandatory inputs to the
offline checker and SDK suites, and are covered by the inventory signature.
Native artifact rebuilds plus unskipped replay on every supported SDK toolchain
remain open release requirements.
`scripts/check_sorafs_reference_sdk_release_evidence.py` now provides the
fail-closed SF-11 release evidence gate for those artifacts, including
cross-artifact `release_manifest_digest_hex` binding from release archives,
per-target supply-chain results, downstream packages, cookbook smoke,
FFI/header contract, and governance approval evidence back to a valid signed
manifest in the same bundle. Payload-free summary anchors cover the release
archive index, signed release-key fingerprint, downstream package index,
cookbook smoke output, header and FFI contract digests, SBOM index,
vulnerability report, and provenance bundle. The supply-chain artifact requires
exact ordered coverage of all five native targets, with binary smoke,
deterministic archive replay, installation, rollback, yank, SBOM, zero
critical/high vulnerability, OIDC identity, and cosign provenance checks for
every target. Signed-manifest evidence requires the exact raw Ed25519 signature
and an authenticated `release_manifest` operation receipt. The builder and checker
independently authenticate the SHA-256-pinned source context, exact policy and
custody trust, separately signed finalized-state observation, and completed
operation through `iroha app sorafs toolkit release-manifest-receipt`. Every canary
identity, digest, revision, and signer-authority fact comes from that closed
native result. Caller-supplied signer labels, unattested receipts, or metadata
claims cannot qualify a release. The service producer and verifier are
implemented; deployed signer and finalized-state adapters and the remaining
release coordinator integration are open G02 work in the closure ledger. The
`scripts/run_sorafs_reference_sdk_release_evidence.py` provides the reviewed
collection planner/runner with dry-run `evidence_contract` output for each
selected release evidence schema and required payload field. The JavaScript SDK
already exposes the Rust-backed
orderbook and PDP reference validators from both the package root and
`@iroha/iroha-js/sorafs`; the Python SDK exposes the same orderbook and PDP
outcome contract from `iroha_python.sorafs` and the package root.
Kotlin/JVM, Java Android, and Swift now expose matching source-level wrappers
through the shared `connect_norito_bridge` native facade. JavaScript, Python,
Kotlin/JVM, Java Android, and Swift also expose the encoded orderbook
order/cancel/settlement-receipt signing helper for callers that already have
Norito payload bytes. Rust, JavaScript, Python, Kotlin/JVM, Java Android, and
Swift now also expose field-level orderbook order/cancel/settlement-receipt
builders that construct, sign, validate, and encode canonical Norito payload
bytes from SDK field values.
JavaScript/TypeScript, Python, Kotlin/JVM, Java Android, Swift, and the managed
C# wrapper also expose the Rust-backed governance DAG block and signed
head-chain validators. The wrappers accept at most 64 contiguous blocks ordered
oldest-to-head, 64 MiB of aggregate input, and 1,024 UTF-8 bytes per diagnostic
label before native dispatch. Histories up to 64 blocks use the full root-to-head
sequence; longer histories use the newest checkpoint-anchored tail. Positive
block and chain validation plus CID-mismatch and block-reordering negatives
share the deterministic
`fixtures/sorafs_manifest/governance/dag_*_v1.to` inventory.
`reference_sdk_validation_inventory_v1.json` is the test-only Ed25519-signed,
schema-closed release-wide inventory for appeal finance, routing/provider
admission, orderbook, PDP, PoR, PoTR, repair, Governance DAG, and moderation. It binds the exact
sorted path set, byte lengths, SHA-256 digests, and canonical JSON/Norito bytes
for 85 payload artifacts, including 41 negative payload vectors, and 35
`ValidationOutcomeV1` files. Its offline checker verifies the trusted
fingerprint and signature and rejects duplicate or nonfinite JSON, path
traversal, missing/extra/substituted files, symlinks, hardlinks, and parent
directory replacement. The twelve cross-SDK profiles comprise nine
fixture-bundle outcomes, a dedicated moderation governance-log-node outcome,
and positive plus negative appeal-finance cancellation outcomes. JavaScript/TypeScript,
Python, Swift, Kotlin/JVM, mirrored Java Android, and C# expose the native
bundle and governance-log-node validation
surfaces with byte-exact fixture tests checked in. Those source and fixture
assets do not constitute a native release run: every native-dependent parity
suite now fails when the ABI-29 bridge or required symbols are unavailable, so
missing, ignored-local, or stale native artifacts remain an explicit red gate
until rebuilt from the final source state and accompanied by authenticated
execution evidence.

Host-native evidence now uses
`scripts/check_native_sdk_artifact.py`. For C/JNI, C#, Node, and Python it
binds one non-linked artifact's stable byte length and SHA-256 to the exact clean
Git commit, calls the bridge probe, requires ABI **exactly** 29, and verifies the
lane's appeal-finance entrypoint inventory. Canonical evidence is reverified
after the build and before the native-dependent suite; noncanonical manifests,
symlinks, hardlinks, byte replacement, source drift, ABI 19/20/21/22, and missing
symbols fail closed. Node staging, loading, and release-provenance collection
also reject missing, dirty, or stale build provenance. The Python native lane is
pinned to Python 3.12 and rejects any skipped reference-validation test.
Apple/Swift and packaged Android/JNI artifacts remain covered by the separate
source-sealed `check_mobile_sdk_artifacts.sh` contract, which verifies every
slice, exact ABI 29, the Android `NativeSignerBridge` JNI contract revision 5,
symbols, hashes, and source identity; they are not represented as host-manifest
lanes. Swift package admission also requires the XCFramework's embedded
`NoritoBridge.artifacts.json` to declare exact ABI 29, and the runtime loader
rejects a parsed manifest whose ABI is missing or differs from the binary
identifier's required ABI before accepting its hash.

These gates deliberately do not qualify ignored, dirty-source, or locally
rebuilt artifacts. No checked-in, clean-source, five-target ABI-29 release
inventory or authenticated execution record currently exists. Clean native
artifacts still must be produced and exercised for Linux x86_64, Linux aarch64,
macOS x86_64, macOS aarch64, and Windows x86_64 before this lane can close.

The C# NuGet source path now consumes exactly those five target-host
`iroha.native-sdk-abi29-artifact.v1` manifests, maps them to `linux-x64`,
`linux-arm64`, `osx-x64`, `osx-arm64`, and `win-x64`, and packages only the
matching `runtimes/<rid>/native/` libraries. The assembler and pre-pack/project
gate reject missing or extra targets/files, source-commit drift, noncanonical
manifests, ABI mismatch, target substitution, and changed artifact bytes. The
post-pack gate rehashes the five ZIP entries, rejects every additional runtime
entry, and the workflow runs a `PackageReference` consumer on each matching
native host. This closes the C# packaging implementation gap only; it does not
claim that a clean five-host run, publication canary, SBOM, or provenance record
has been collected.

SwiftPM is the sole supported Swift packaging path. `IrohaSwift/VERSION` owns
the Swift package, tag and XCFramework archive version. The package owner
authenticates the immutable ZIP, embedded ABI-29 manifest, closed inventory,
source, locks and tools. Qualify both the archive consumer and an ordinary
public `IrohaSwift` dependency in Release with real native execution and no
unsafe linker flags. Public native Swift readiness still requires an immutable
release asset, installed package consumer and signed provenance; host/simulator
checks do not establish physical-device qualification.

The existing `sorafs_manifest` crate exposes `ValidationOutcomeV1`,
`validate_provider_advert_bytes`, `validate_provider_admission_envelope_bytes`,
`validate_replication_order_bytes`,
`validate_signed_replication_order_bytes`, `validate_orderbook_payload_bytes`,
`validate_por_challenge_proof_bytes`,
`validate_pdp_commitment_challenge_proof_bytes`, `validate_potr_receipt_bytes`,
`validate_repair_payload_bytes`, and the `sorafs_car` crate exposes
`validate_manifest_car_replay` and
`validate_manifest_car_replay_bytes`. The `iroha app sorafs toolkit validate advert` /
`iroha app sorafs toolkit validate admission` / `iroha app sorafs toolkit validate order` /
`iroha app sorafs toolkit validate orderbook` / `iroha app sorafs toolkit validate por` /
`iroha app sorafs toolkit validate pdp` / `iroha app sorafs toolkit validate potr` /
`iroha app sorafs toolkit validate repair` / `iroha app sorafs toolkit validate bundle` /
`iroha app sorafs toolkit validate governance` / `iroha app sorafs toolkit release-manifest` CLI commands
cover Norito `ProviderAdvertV1`,
`ProviderAdmissionEnvelopeV1`, `ReplicationOrderV1`, `PorChallengeV1`,
`PorProofV1`, `PdpCommitmentV1`, `PdpChallengeV1`, `PdpProofV1`,
`PotrReceiptV1`, orderbook/settlement payloads, and repair payloads,
fixture-directory bundle cross-link checks, governance log node
validation, governance DAG block validation, signed governance DAG head-chain
validation, provider advert signing, signed replication-order envelopes, and
governance log node Ed25519 signing, plus strict native raw Ed25519 release
manifest signing and verification.
`soranet_trustless_verifier --validation-outcome` emits the same
`ValidationOutcomeV1` contract for manifest/CAR replay.

## Architecture Overview
| Component | Purpose | Notes |
|-----------|---------|-------|
| `crates/sorafs_manifest::reference` | Core library module providing validation/signing helpers, policy enforcement, and error outcomes. | Reuses canonical `sorafs_manifest` payload modules and `sorafs_car` replay helpers; no duplicate codecs. |
| `iroha` (binary) | CLI wrapping the reference validators with task-focused subcommands and consistent output. | The checked-in first-release wrapper uses explicit bounded argument parsing and `norito::json`; it has no direct `serde_json` dependency. |
| `reference_ffi` helpers | C ABI surface for native SDK adapters built on top of the Rust validators. | Implemented: returns `ValidationOutcomeV1` Norito JSON buffers plus explicit free function; `crates/sorafs_manifest/include/sorafs_reference.h` is the checked C header for downstream bindings. `connect_norito_bridge` also exposes mobile SDK orderbook signing and field-level builder entry points. |
| `fixtures/documentation/sorafs_reference_sdk/` | Runnable cookbook with ready-to-run CLI and SDK smoke scenarios plus committed sample payloads. | Mirrors committed fixtures and exercises validator, signing, bundle, and manifest/CAR replay paths. |

Internal modules (library):
- `validator::advert`, `validator::admission`, `validator::order`, `validator::por`, `validator::potr`, `validator::repair`, `validator::governance`.
- `policy` module encapsulates default thresholds (TTLs, SLAs, retry budgets).
- `outcome` module implements `ValidationOutcomeV1` (see below).
- Signing helpers expose implemented builders for adverts, signed
  replication-order envelopes, SFM-2 orderbook order/cancel/receipt payloads,
  and governance log nodes; signed replication orders use the
  `sorafs.replication_order.signature.v1` domain string and canonical Norito
  order-envelope bytes.
- The orderbook encoded-payload signing helper is available as
  `sorafs_manifest::sign_orderbook_payload_bytes_ed25519_v1(...)` and through
  JavaScript `signOrderbookPayload(...)`, Python
  `sign_orderbook_payload(...)`, Kotlin/JVM
  `SorafsReferenceValidators.signOrderbookPayload(...)`, Java Android
  `SorafsReferenceValidators.signOrderbookPayload(...)`, and Swift
  `SorafsReferenceValidators.signOrderbookPayload(...)` for callers that
  already have Norito `OrderRequestV1`, `OrderCancelV1`, or
  `SettlementReceiptV1` bytes.
- Field-level orderbook builders are available in Rust as
  `build_signed_orderbook_order_request_bytes_ed25519_v1(...)`,
  `build_signed_orderbook_order_cancel_bytes_ed25519_v1(...)`, and
  `build_signed_orderbook_settlement_receipt_bytes_ed25519_v1(...)`, in
  JavaScript as `buildSignedOrderbookOrderRequest(...)`,
  `buildSignedOrderbookOrderCancel(...)`, and
  `buildSignedOrderbookSettlementReceipt(...)`, and in Python as
  `build_signed_orderbook_order_request(...)`,
  `build_signed_orderbook_order_cancel(...)`, and
  `build_signed_orderbook_settlement_receipt(...)`. Kotlin/JVM, Java Android,
  and Swift expose the same field-level builders through the shared
  `connect_norito_bridge` native facade.

## CLI Surface
All commands accept `--format {table,json,yaml}` (default `table`) and `--telemetry-out <path>` to write the raw `ValidationOutcomeV1`.

Current implementation slice: `cargo run -p iroha_cli --bin iroha -- app sorafs toolkit validate advert --input <advert.to> --format json` validates Norito `ProviderAdvertV1` payloads, including canonical body validation and Ed25519 signature verification. `cargo run -p iroha_cli --bin iroha -- app sorafs toolkit validate admission --input <envelope.to> --format json` validates Norito `ProviderAdmissionEnvelopeV1` payloads, including structural policy, digest binding, and council signature verification; add `--renewal <renewal.to>` to validate governed renewal payloads against the previous envelope, or `--revocation <revocation.to>` to validate revocation digests and council signatures against the governed envelope. `cargo run -p iroha_cli --bin iroha -- app sorafs toolkit validate order --order <order.to> --format json` validates Norito `ReplicationOrderV1` payloads against the canonical order schema, chunker registry handle rules, provider assignments, and SLA/deadline policy; `cargo run -p iroha_cli --bin iroha -- app sorafs toolkit validate order --signed-order <signed-order.to> --format json` validates `SignedReplicationOrderV1` envelopes and verifies Ed25519 signatures over the domain-separated canonical order signing bytes. `cargo run -p iroha_cli --bin iroha -- app sorafs toolkit validate orderbook --kind settlement-receipt --input <receipt.to> --format json` validates Norito orderbook and streaming-settlement payloads, including structural constraints, fee/timestamp policy, signature material, byte ranges, and settlement accounting. `cargo run -p iroha_cli --bin iroha -- app sorafs toolkit validate por --challenge <challenge.to> --proof <proof.to> --format json` validates Norito `PorChallengeV1` and `PorProofV1` payloads, pair binding, deadline policy, and sample coverage. `cargo run -p iroha_cli --bin iroha -- app sorafs toolkit validate pdp --commitment <commitment.to> --challenge <challenge.to> --proof <proof.to> --format json` validates Norito `PdpCommitmentV1`, `PdpChallengeV1`, and `PdpProofV1` payloads, commitment/challenge/proof binding, sample windows, coverage, tree roots, and signature material. `cargo run -p iroha_cli --bin iroha -- app sorafs toolkit validate potr --receipt <receipt.to> --profile hot --format json` validates Norito `PotrReceiptV1` payloads, latency/deadline consistency, optional tier profile, range bounds, timestamps, and detached signatures. `cargo run -p iroha_cli --bin iroha -- app sorafs toolkit validate repair --kind task --input <repair-task.to> --format json` validates bounded Norito repair task records, evidence, reports, slash proposals, escalation policy/approval payloads, task events, and audit events; retired signed-auditor and worker-envelope selectors are rejected because command authentication uses the canonical Iroha `SignedTransaction` path. `cargo run -p iroha_cli --bin iroha -- app sorafs toolkit validate bundle --bundle fixtures/sorafs_manifest --now 120 --format json` validates known fixture-directory artifacts, validates discovered orderbook and PDP payload fixtures, checks PoR challenge/proof binding, checks PDP commitment/challenge/proof binding, enforces shared manifest digests for order/proof/receipt/repair artifacts, verifies provider-admission provider consistency, and checks manifest-bearing providers against replication-order assignments. `cargo run -p iroha_cli --bin iroha -- app sorafs toolkit validate governance --node fixtures/sorafs_manifest/governance/node_v1.to --cid hex:22cc36bfe1ea242afc1680bed4ab5b707e34316cb8c24c3439db7668d968b3a2 --format json` validates `GovernanceLogNodeV1` payload shape, embedded payload policy, publisher metadata, signature material, Ed25519 and Dilithium3/ML-DSA publisher signature verification, and required node-CID binding. `cargo run -p iroha_cli --bin iroha -- app sorafs toolkit validate governance --block <block.to> --cid hex:<block-cid-hex> --format json` validates a Norito `GovernanceDagBlockV1`, recomputes its canonical block CID, checks embedded node policy and signature material, and verifies the block publisher signature. `cargo run -p iroha_cli --bin iroha -- app sorafs toolkit validate governance --head <head.to> --block <block-0.to> --block <block-1.to> --format json` validates a signed `GovernanceDagHeadV1` against a parent-linked block chain, including head signature, expected head CID, chain topology, and block-count binding. `cargo run -p iroha_cli --bin iroha -- app sorafs toolkit sign --kind advert --input <advert.to> --out <signed-advert.to> --key <runtime-key-file> --now 120 --format json` signs the canonical advert body with an Ed25519 seed supplied at runtime, `cargo run -p iroha_cli --bin iroha -- app sorafs toolkit sign --kind order --input <order.to> --out <signed-order.to> --key <runtime-key-file> --format json` signs the domain-separated canonical order envelope, `cargo run -p iroha_cli --bin iroha -- app sorafs toolkit sign --kind orderbook --payload-kind order-request --input <orderbook-order.to> --out <signed-orderbook-order.to> --key <runtime-key-file> --format json` signs SFM-2 orderbook order, cancel, or settlement-receipt payloads, and `cargo run -p iroha_cli --bin iroha -- app sorafs toolkit sign --kind governance --input <node.to> --out <signed-node.to> --key <runtime-key-file> --format json` signs the canonical governance node payload. `cargo run -p sorafs_car --features cli,dev-tools --bin soranet_trustless_verifier -- --manifest <manifest.to> --car <payload.car> --validation-outcome --generated-at <unix-seconds>` replays `ManifestV1` policy, CARv2 roots, CAR digest/size, content length, chunk plan, payload digest, and PoR root into `ValidationOutcomeV1`. These sign and validation commands write or print output only after validation succeeds where applicable and return code `0` for success or `2` for validation/policy/signature/Norito payload errors. V1 command, kind, and flag spellings are exact; compatibility aliases, case folding, and surrounding whitespace are rejected.

| Command | Description | Key flags | Input |
|---------|-------------|-----------|-------|
| `iroha app sorafs toolkit validate advert` | Validate `ProviderAdvertV1` payloads (signature, TTL, capability set). | Implemented: `--input <file>`, `--format table\|json\|yaml`, `--telemetry-out <path>`, `--now <unix-seconds>`. Governed policy overrides belong to a signed release-wrapper policy document; the current local validator uses deterministic defaults. | Norito bytes. |
| `iroha app sorafs toolkit validate admission` | Verify `ProviderAdmissionEnvelopeV1` onboarding, renewal, and revocation payloads (schema, digest bindings, retention epoch, council signatures). | Implemented: `--input <file>`, optional `--renewal <file>` or `--revocation <file>`, `--format table\|json\|yaml`, `--telemetry-out <path>`. External governance keyset selection remains a signed deployment-policy concern; the local validator verifies the key material encoded in the governed envelope. | Norito bytes. |
| `iroha app sorafs toolkit validate order` | Check `ReplicationOrderV1` payloads (schema, manifest digest presence, chunk profile, provider assignments, SLA/deadline policy). | Implemented: `--order <file>` for bare orders, `--signed-order <file>` for `SignedReplicationOrderV1` envelopes, `--format table\|json\|yaml`, `--telemetry-out <path>`. Manifest/CAR replay is handled by `soranet_trustless_verifier --validation-outcome` to keep CAR parsing in `sorafs_car`. | Norito bytes. |
| `iroha app sorafs toolkit validate orderbook` | Validate orderbook and streaming-settlement payloads (`OrderRequestV1`, `OrderCancelV1`, `TradeEventV1`, `SettlementChannelV1`, `SettlementReceiptV1`). | Implemented: exact `--kind <payload-kind> --input <file>`, `--format table\|json\|yaml`, `--telemetry-out <path>`. Pure Rust helpers cover pair and full-book matching, fees, escrow, channels, receipts, and canonical signatures. The authoritative native ledger and supervised worker now own bounded price-time matching, atomic custody mutation, and authority/signature enforcement. Remaining SF-11 gaps are rebuilt native artifacts and byte-identical replay on every supported SDK toolchain, published per-target archives and binding packages, and genuine downstream install/smoke evidence. | Norito bytes. |
| `iroha app sorafs toolkit validate por` | Validate `PorChallengeV1` and `PorProofV1` pairs (typed payloads, challenge/manifest/provider binding, deadline, sample coverage). | Implemented: `--challenge <file>`, `--proof <file>`, `--format table\|json\|yaml`, `--telemetry-out <path>`. Manifest/CAR replay is implemented by `soranet_trustless_verifier --validation-outcome`; governed epoch overrides belong to signed release-wrapper policy. | Norito bytes. |
| `iroha app sorafs toolkit validate pdp` | Validate `PdpCommitmentV1`, `PdpChallengeV1`, and `PdpProofV1` payloads plus commitment/challenge/proof binding. | Implemented: `--commitment <file>`, `--challenge <file>`, `--proof <file>`, with pair or single-payload validation accepted where useful, `--format table\|json\|yaml`, `--telemetry-out <path>`. Bundle validation discovers committed PDP fixtures and enforces manifest/provider/sample binding. | Norito bytes. |
| `iroha app sorafs toolkit validate potr` | Validate `PotrReceiptV1` receipts (deadline/latency consistency, tier profile, range bounds, timestamps, signatures). | Implemented: `--receipt <file>`, optional `--profile hot\|warm\|archive`, `--format table\|json\|yaml`, `--telemetry-out <path>`. Committed PoTR receipt fixtures are covered by bundle validation; live probe-bundle and orchestrator metric cross-checks are rollout evidence. | Norito bytes. |
| `iroha app sorafs toolkit validate repair` | Validate bounded reference/publication payloads (`RepairEvidenceV1`, `RepairReportV1`, `RepairTaskRecordV1`, slash proposals, escalation policy/approval, and task/audit events). | Implemented: exact `--kind <payload-kind> --input <file>`, plus `--format table\|json\|yaml` and `--telemetry-out <path>`. Retired signed-auditor and worker-envelope kinds/flags are rejected; command authentication belongs to the canonical Iroha `SignedTransaction` path. | Norito bytes. |
| `iroha app sorafs toolkit validate governance` | Validate `GovernanceLogNodeV1` payloads, `GovernanceDagBlockV1` blocks, and signed `GovernanceDagHeadV1` chains. | Implemented: `--node <file>` with required `--cid <node-cid>`; `--block <file>` with optional `--cid <block-cid\|hex:HEX>`; or `--head <file> --block <file> [--block <file>...]`, plus `--format table\|json\|yaml` and `--telemetry-out <path>`. Node validation covers embedded payload policy, publisher metadata, Ed25519 and Dilithium3/ML-DSA publisher signatures, and required node-CID binding. Block/head validation covers canonical block-CID derivation, embedded node policy, block signatures, parent linkage, signed head binding, and block-count binding. | Norito bytes. |
| `iroha app sorafs toolkit validate bundle` | Run a composite check on a fixture bundle (admission artifacts plus order/proofs/receipts/repair payloads and orderbook fixtures). | Implemented: `--bundle <dir>`, `--format table\|json\|yaml`, `--telemetry-out <path>`, `--now <unix-seconds>`. Manifest/CAR policy replay is implemented by `soranet_trustless_verifier --validation-outcome`. | Directory matching fixture layout. |
| `iroha app sorafs toolkit release-manifest` | Verify the canonical aggregate release-manifest signature. | Verification requires `--manifest <file>`, `--public-key <raw-32-byte-file>`, `--public-key-fingerprint <lowercase-sha256-hex>`, and `--signature <raw-64-byte-file>`. Inputs are bounded direct regular files and signatures use strict Ed25519 verification. Release signing remains external to this validator. | Exact aggregate release-manifest bytes plus raw Ed25519 verification material. |
| `soranet_trustless_verifier --validation-outcome` | Replay `ManifestV1` policy and a full CARv2 stream into the reference outcome contract. | Implemented: `--manifest <manifest.to>`, `--car <payload.car>`, optional `--config <toml>`, `--json-out <path>`, `--quiet`, `--generated-at <unix-seconds>`. | Manifest Norito or JSON plus CAR bytes. |
| `iroha app sorafs toolkit sign` | Produce signed reference payloads using operator or governance keys. | Implemented: `--kind advert --input <advert.to> --out <signed-advert.to> (--key-hex <hex> \| --key <path>)`, `--kind order --input <order.to> --out <signed-order.to> (--key-hex <hex> \| --key <path>)`, `--kind orderbook --payload-kind order-request\|order-cancel\|settlement-receipt --input <payload.to> --out <signed-payload.to> (--key-hex <hex> \| --key <path>)`, `--kind governance --input <node.to> --out <signed-node.to> (--key-hex <hex> \| --key <path>)`, `--format table\|json\|yaml`, `--telemetry-out <path>`, `--now <unix-seconds>` for adverts. | Norito bytes -> Norito bytes. |

Exit codes: `0` success, `2` validation/policy/signature errors, `3` I/O errors, `4` configuration errors, `10` internal faults.

## FFI Surface
`crates/sorafs_manifest::reference_ffi` exposes a C ABI for SDK bindings that
need the Rust reference validators without linking Rust-native APIs. The
`connect_norito_bridge` facade re-exports the orderbook and PDP validator
surface plus governance DAG block/head-chain validation for Kotlin/JVM, Java
Android, Swift, and C# consumers that already load the shared mobile bridge.
The governance head-chain ABI uses a bounded array of payload/label
descriptors ordered from root to head. Each
validator returns a `SorafsReferenceFfiBuffer` containing `ValidationOutcomeV1`
rendered with Norito JSON; callers must release it with
`sorafs_reference_free_buffer`. The public C binding contract lives at
`crates/sorafs_manifest/include/sorafs_reference.h`; the
`ci/check_sorafs_reference_ffi_header.sh` guard compares that header with
`reference_ffi.rs`, verifies selector values, and syntax-checks the header as C
and C++ when local compilers are available.

Implemented functions cover provider adverts, admission envelopes, admission
renewals, admission revocations, replication orders, signed replication-order
envelopes, orderbook payloads, PoR challenge/proof pairs, PDP
commitment/challenge/proof payloads, PoTR receipts, repair payloads,
governance log nodes, and fixture bundle payload arrays:

- `sorafs_reference_validate_provider_advert_json`
- `sorafs_reference_validate_provider_admission_json`
- `sorafs_reference_validate_provider_admission_renewal_json`
- `sorafs_reference_validate_provider_admission_revocation_json`
- `sorafs_reference_validate_replication_order_json`
- `sorafs_reference_validate_signed_replication_order_json`
- `sorafs_reference_validate_orderbook_json`
- `sorafs_reference_validate_por_json`
- `sorafs_reference_validate_pdp_commitment_json`
- `sorafs_reference_validate_pdp_challenge_json`
- `sorafs_reference_validate_pdp_proof_json`
- `sorafs_reference_validate_pdp_commitment_challenge_json`
- `sorafs_reference_validate_pdp_challenge_proof_json`
- `sorafs_reference_validate_pdp_json`
- `sorafs_reference_validate_potr_json`
- `sorafs_reference_validate_repair_json`
- `sorafs_reference_validate_governance_json`
- `sorafs_reference_validate_governance_dag_block_json`
- `sorafs_reference_validate_governance_dag_head_chain_json`
- `sorafs_reference_validate_bundle_json`

FFI selectors are exported as constants for repair payload kinds, bundle payload
kinds including orderbook and PDP bundle members, orderbook payload kinds, and
PoTR profiles. Invalid selectors or null pointers paired with non-zero lengths
return `SFS-FFI-001` instead of unwinding across the ABI. JavaScript package
wrappers for orderbook, PDP, and governance DAG validation are exposed through
the native `iroha_js_host` binding; Python wrappers use `iroha_python_rs`;
Kotlin/JVM, Java Android, Swift, and C# wrappers use `connect_norito_bridge`.
The bridge exports
`connect_norito_sorafs_reference_validate_governance_dag_block_json` and
`connect_norito_sorafs_reference_validate_governance_dag_head_chain_json`;
the JVM namespaces mirror both through JNI. Remaining downstream work is
signed release packaging, publication, and live SDK smoke evidence for those
bindings.

## Validation Policies
Default policy constants used by the implemented validators:
- Advert TTL must be non-zero and ≤ 24h; `provider_id` must be non-zero and capability metadata must pass the canonical advert schema.
- Admission envelopes must reference approved senior council keyset (multi-signature) and admission window ≤ 7 days.
- Replication orders validate:
  - Manifest digest presence and order/assignment binding.
  - Order version supported by local `sorafs_manifest`.
  - Pricing schedule conforms to `sorafs_pricing.md` tiers.
- Orderbook payloads validate:
  - Order/cancel/trade/channel/receipt schema versions and non-zero identifiers.
  - Positive price, quantity, escrow, byte-count, debit, timestamp, and nonce
    fields where required.
  - Ed25519 key/signature lengths and settlement accounting where provider
    credit plus fee must equal buyer debit.
- Manifest/CAR replay validates manifest policy, declared CAR digest and size,
  content length, root CID, chunk profile, chunk digests, payload digest, chunk
  plan, and PoR root through `sorafs_car::validate_manifest_car_replay*` and
  `soranet_trustless_verifier --validation-outcome`.
- PoR:
  - Challenge/proof share identical seed, epoch, and manifest digest (via `derive_challenge_seed`).
  - Response deadline must be after issue time, and proof responses must arrive before the encoded deadline; governed deadline changes are release-wrapper policy, not ad hoc CLI flags.
  - Sample coverage meets tier thresholds from SF-9.
- PDP:
  - Commitments, challenges, and proofs share manifest digest, provider ID, epoch, sample window, coverage, and deterministic sample labels.
  - Hot/segment roots, tree heights, proof leaves, and signature material must pass structural checks before pair binding is accepted.
  - PDP bundle validation is fixture-backed and fail-closed until the SF-13 runtime admission path is enabled.
- PoTR:
  - Probe durations respect hot/warm/cold SLAs (90s / 5m / 30m).
  - Receipt signature matches provider key; aggregated proofs cross-check with orchestrator metrics if provided.
- Repair tasks:
  - Evidence matches PoR/PoTR failure digests.
  - Escalation reason required for `escalated` status; `repair_task_id` must be the exact 32-byte native task identifier and match the supplied committed repair-task projection.
- Governance nodes:
  - Node CID can be compared against caller-supplied input.
  - Payload kind resolved; unsupported types flagged.
  - DAG blocks recompute canonical block CID bytes and verify embedded node and
    block publisher signatures.
  - Signed DAG heads verify parent-linked chains, expected head CID, and
    advertised block count before acceptance.

Governed policy override support is intentionally outside the local deterministic validator. Release wrappers that need overrides should load a Norito policy document with an allowlist of fields such as `advert_ttl_min` and `por_deadline_max`, and production pipelines must require a governed signature before applying overrides.

## Error & Outcome Contract
`ValidationOutcomeV1` (Norito + JSON) includes:
```norito
struct ValidationOutcomeV1 {
    status: ValidationStatus, // Ok | Error
    code: String,             // SFS-VAL-001 etc.
    category: ValidationCategory, // validation | policy | signature | io | norito | internal
    message: String,
    action: Option<String>,
    docs_url: Option<String>,
    telemetry_tags: Vec<String>,
    context: ValidationContextV1,
    inputs: Vec<ValidationInputV1>, // file paths / CIDs
    version: u8,                    // outcome schema version
    generated_at: Timestamp,
}
```
`ValidationContextV1` is emitted as structured key/value fields (manifest CID, provider ID, etc.). The outcome is printed by CLI (`table` format compresses key fields).

Error catalogue:
- `SFS-OK-000` validation succeeded.
- `SFS-VAL-001` required digest or identifier invalid or mismatch.
- `SFS-VAL-002` unsupported schema version.
- `SFS-VAL-003` chunk profile incompatibility.
- `SFS-VAL-004` provider advert structure invalid.
- `SFS-VAL-005` replication order structure invalid.
- `SFS-VAL-006` provider admission envelope structure invalid.
- `SFS-VAL-007` provider admission digest binding mismatch.
- `SFS-VAL-008` PoR challenge structure invalid.
- `SFS-VAL-009` PoR proof structure invalid.
- `SFS-VAL-010` PoTR receipt structure invalid.
- `SFS-SIG-001` invalid signature.
- `SFS-SIG-002` provider admission council signature invalid.
- `SFS-SIG-003` PoTR receipt signature invalid.
- `SFS-SIG-005` governance log signature material invalid or publisher verification failed.
- `SFS-SIG-006` signed replication order or governance DAG block signature invalid.
- `SFS-SIG-007` orderbook or governance DAG head signature material invalid.
- `SFS-SIG-008` PDP proof signature material missing or malformed.
- `SFS-POL-001` advert TTL violation.
- `SFS-POL-002` PoR deadline exceeded.
- `SFS-POL-003` replication order deadline or SLA policy violation.
- `SFS-POL-004` provider admission retention policy violation.
- `SFS-POL-005` repair timestamp or SLA deadline policy violation.
- `SFS-POL-006` manifest pin policy failed during manifest/CAR replay.
- `SFS-POL-007` orderbook timestamp, nonce, or fee policy violation.
- `SFS-CAR-001` CAR stream replay failed against manifest commitments.
- `SFS-CAR-002` trustless manifest/CAR replay metadata derivation failed.
- `SFS-POR-001` missing sample coverage.
- `SFS-POR-002` proof sample digest mismatch.
- `SFS-POR-003` PoR challenge/proof binding mismatch.
- `SFS-PDP-001` PDP sample window or coverage invalid.
- `SFS-PDP-002` PDP commitment, challenge, or proof structure invalid.
- `SFS-PDP-003` PDP commitment/challenge/proof binding mismatch.
- `SFS-POTR-001` deadline proof late.
- `SFS-POTR-002` PoTR receipt tier mismatch.
- `SFS-OBK-001` orderbook payload structure invalid.
- `SFS-OBK-002` orderbook settlement accounting invalid.
- `SFS-REP-001` repair evidence is incomplete or internally invalid.
- `SFS-REP-002` repair evidence, report, reference task record, slash proposal,
  escalation policy/approval, task event, or audit event structure invalid.
- `SFS-BND-001` fixture bundle payload validation failed or too few linkable artifacts were present.
- `SFS-BND-002` fixture bundle artifacts name different manifest digests.
- `SFS-BND-003` fixture bundle provider links disagree with each other or with replication-order assignments.
- `SFS-GOV-001` governance log node structure or embedded payload validation failed.
- `SFS-GOV-002` repair escalation or slash governance payload invalid.
- `SFS-GOV-003` governance log node CID does not match the expected CID.
- `SFS-GOV-004` governance DAG block CID does not match the expected CID or canonical payload.
- `SFS-GOV-005` governance DAG block structure or embedded node validation failed.
- `SFS-GOV-006` governance DAG chain topology, parent linkage, or expected head validation failed.
- `SFS-GOV-007` governance DAG head manifest structure failed validation.
- `SFS-GOV-008` governance DAG head block-count binding failed validation.
- `SFS-FFI-001` FFI caller supplied an invalid ABI argument.
- `SFS-FFI-002` FFI panicked or failed to render outcome JSON.
- `SFS-IO-001` input read failure.
- `SFS-NORITO-001` decode error.
- `SFS-INT-001` internal panic/unexpected.

CLI prints `docs_url` pointing to `https://docs.iroha.tech/`.

## Library API Highlights
- `sorafs_manifest::reference::validate_provider_advert_bytes(...)`.
- `sorafs_manifest::reference::validate_provider_admission_envelope_bytes(...)`.
- `sorafs_manifest::reference::validate_provider_admission_renewal_bytes(...)`.
- `sorafs_manifest::reference::validate_provider_admission_revocation_bytes(...)`.
- `sorafs_manifest::reference::validate_replication_order_bytes(...)`.
- `sorafs_manifest::reference::validate_signed_replication_order_bytes(...)`.
- `sorafs_manifest::reference::validate_orderbook_payload_bytes(...)`.
- `sorafs_manifest::reference::validate_por_challenge_proof_bytes(...)`.
- `sorafs_manifest::reference::validate_pdp_commitment_bytes(...)`.
- `sorafs_manifest::reference::validate_pdp_challenge_bytes(...)`.
- `sorafs_manifest::reference::validate_pdp_proof_bytes(...)`.
- `sorafs_manifest::reference::validate_pdp_commitment_challenge_bytes(...)`.
- `sorafs_manifest::reference::validate_pdp_challenge_proof_bytes(...)`.
- `sorafs_manifest::reference::validate_pdp_commitment_challenge_proof_bytes(...)`.
- `sorafs_manifest::reference::validate_potr_receipt_bytes(...)`.
- `sorafs_manifest::reference::validate_repair_payload_bytes(...)`.
- `sorafs_manifest::reference::validate_appeal_finance_cancel_asset_lock_bytes(...)`.
- `sorafs_manifest::reference::validate_fixture_bundle_payloads(...)`.
- `sorafs_manifest::reference::validate_governance_log_node_bytes(...)`.
- `sorafs_manifest::reference::validate_governance_dag_block_bytes(...)`.
- `sorafs_manifest::reference::validate_governance_dag_head_chain_bytes(...)`.
- `sorafs_car::validate_manifest_car_replay_bytes(...)` and
  `sorafs_car::validate_manifest_car_replay(...)`.
- `reference_ffi` functions return `SorafsReferenceFfiBuffer` values
  containing `ValidationOutcomeV1` Norito JSON for the same validator families.

Public APIs avoid direct filesystem dependencies; CLI binaries own file I/O and
convert decoded or raw Norito payloads into the shared validation functions.

## Integration & Automation
- **Cookbook smoke:** `fixtures/documentation/sorafs_reference_sdk/run_reference_sdk_cookbook.sh`
  runs the committed validator, signing, bundle, and manifest/CAR replay
  scenarios.
- **Cross-SDK canonical fixtures:** the ordered `cancel_asset_lock_fixtures`,
  `generate_pdp_fixtures`, and `generate_por_fixtures` pipeline deterministically
  regenerates the closed fixture tree and signed inventory under
  `fixtures/sorafs_manifest/`. The checked-in inventory binds 85 payload
  artifacts, 35 exact outcome files, and 41 negative payload vectors. The
  typed `cancel_asset_lock_fixtures` generator and SDK tests freeze the
  appeal-finance
  `CancelAssetLock { escrow_id, expected_remaining_amount }` hard cut and its
  missing-field, retired nested-identifier, zero, and noncanonical-quantity
  negatives.
  `EscrowId` keeps its nominal Rust and `IntoSchema` identity while V1 binary
  and JSON serialization delegate directly to `Hash`: the field is exactly
  `0x20 <32-byte hash>` on the wire and one scalar `hash:...` JSON literal.
  The 85-byte canonical frame is byte-exact; the redundant 86-byte
  `0x21 0x20 <hash>` representation and one-element JSON arrays are rejected.
  All eight generated files are present and covered by the resealed inventory.
  `ci/check_sorafs_fixtures.sh` runs the pipeline in two isolated copies and
  requires checked-in/pass-one/pass-two byte identity. Fixture lookup is
  mandatory, so absence is a test failure rather than a capability skip.
  Nine fixture-bundle profiles cover routing/provider admission, orderbook,
  PDP, PoR, PoTR, and repair; a tenth profile exercises moderation through the
  dedicated governance-log-node validator; and the eleventh and twelfth
  profiles exercise the positive and zero-quantity-negative appeal-finance
  cancellation outcomes. The Governance DAG block/head vectors are bound by
  the same closed inventory.
  `scripts/check_sorafs_reference_sdk_fixtures.py` verifies the inventory
  without network access. JavaScript/TypeScript, Python, Swift, Kotlin/JVM,
  mirrored Java Android, and C# have native wrapper and byte-exact fixture test
  coverage checked in. JavaScript/TypeScript, Swift, Kotlin/JVM, mirrored Java
  Android, C#, and Python native-dependent tests fail when the exact ABI-29
  bridge or required symbols are absent; a source-contract regression gate pins
  those fail-closed markers, and the Python lane additionally rejects any
  skipped reference test.
  These are source and workflow contracts, not freshness evidence. The
  available Node, Python, C/JNI, Swift, and C# outputs are stale or mixed, so no
  native-dependent suite is qualified. Qualification requires one clean
  pinned-commit ABI-29 rebuild and skip-free parity replay across the five
  native release targets.
- **Release packaging:** `scripts/package_iroha_cli_release.sh` builds or
  packages `iroha`, stages `include/sorafs_reference.h`, runs fixture
  smoke checks, records per-file, binary, FFI-header, archive, and manifest
  digests under an untracked output directory. It emits no signature or public
  key. The release coordinator adds every target manifest and checksum to the
  final aggregate `release_manifest.json`. Qualification requires the configured
  release-manifest producer to sign those exact bytes and commit its receipt,
  followed by the pinned native signature and receipt verifiers. The remaining
  coordinator and deployment adapters are recorded as open G02 work.
- **CI guard:** PR checks can run `iroha app sorafs toolkit validate bundle` and the cookbook
  script against committed fixtures; `ci/check_sorafs_reference_ffi_header.sh`
  fails if Rust FFI exports, selector constants, or C signatures drift from the
  checked header. Dedicated fixture and native-parity workflows are checked in
  as `.github/workflows/sorafs-fixtures-nightly.yml` and
  `.github/workflows/sorafs-orchestrator-sdk.yml`; the mobile and C# workflows
  additionally enforce source-sealed or target-native package replay.
- **Telemetry:** CLI `--telemetry-out` writes the raw `ValidationOutcomeV1`
  contract so operators can scrape `telemetry_tags` and error codes.
- **Torii integration:** production upload validation remains a rollout item; no
  dedicated upload-validation route is currently shipped.

## Testing & Fixtures
- Unit tests cover policy edge cases, error codes, FFI error handling, and
  positive validation paths in `crates/sorafs_manifest/src/reference.rs` and
  `reference_ffi.rs`.
- CLI tests cover argument parsing, output formats, signing paths, and failure
  codes for `iroha`, including committed orderbook and PDP fixture
  discovery from `iroha app sorafs toolkit validate bundle --bundle fixtures/sorafs_manifest`.
- The cookbook replays committed fixtures for adverts, admission, orders,
  orderbook settlement receipts, PoR, PDP, PoTR, repair, governance nodes,
  bundle cross-links, and manifest/CAR replay. The canonical signed reference
  SDK inventory covers routing/provider admission, orderbook, PDP, PoR, PoTR,
  repair, Governance DAG, and moderation, while its strict offline checker and
  deterministic-regeneration test bind every artifact and outcome byte.
- Cross-SDK fixture tests compare nine bundle profiles, the dedicated
  moderation governance-log-node outcome, and positive plus negative
  appeal-finance cancellation outcomes against exact
  `ValidationOutcomeV1` bytes. Release completion still requires running the
  Rust regeneration test and every native-dependent SDK parity suite against
  rebuilt current-ABI artifacts without capability skips.
- Release smoke checks run through `scripts/package_iroha_cli_release.sh`.
- Cross-target release evidence is still a production gate; archive published
  checksums and smoke outputs for each supported release target and require the
  SF-11 release evidence gate to pass before declaring those artifacts
  production-ready.

## Documentation Requirements
- Implemented: `fixtures/documentation/sorafs_reference_sdk/` sample scripts, README, and
  smoke runner that emits `ValidationOutcomeV1` JSON for committed fixtures.
- Implemented: portal reference SDK error catalogue at
  `https://docs.iroha.tech/`.
- Implemented: the operator, metrics, and binding-generation guides below cover
  the local release helper, `ValidationOutcomeV1` telemetry contract, checked C
  header, and downstream package evidence handoff. Final release-specific URLs,
  signatures, and package versions remain SF-11 release evidence.

### Operator Guide

1. Build or package one target at a time with
   `scripts/package_iroha_cli_release.sh`, keeping generated output under
   an untracked `dist/iroha-release/<target>/` directory. Commit only
   `dist/.gitkeep`.
2. For each supported target, archive the helper-generated binary, release
   archive, `.sha256` files, unsigned manifest JSON, FFI header copy, and
   smoke-output hash. Add those paths and digests to the canonical aggregate
   release manifest. Do not persist runtime signing material, tokens, or raw
   payload fixtures in per-target release evidence.
3. Run `fixtures/documentation/sorafs_reference_sdk/run_reference_sdk_cookbook.sh` against
   the staged binaries by setting `IROHA_CLI_BIN` and
   `SORANET_TRUSTLESS_VERIFIER_BIN`. Attach only the outcome digests and
   payload-free smoke summary to SF-11 evidence.
4. Before promotion, run
   `scripts/run_sorafs_reference_sdk_release_evidence.py
   @scripts/examples/sorafs_reference_sdk_release_collection.args.example
   --dry-run` to capture the exact verifier command, thresholds, and
   `evidence_contract` schema/field requirements, then execute the runner
   against reviewed evidence paths.

### Metrics Guide

`iroha` commands accept `--telemetry-out <path>` and write the raw
`ValidationOutcomeV1` JSON contract. Operators should translate those files into
counter-style telemetry keyed by `status`, `code`, `category`, validator command
family, and every stable entry in `telemetry_tags`. Keep `docs_url`, `action`,
and bounded `context` fields as log attributes for triage, but do not export raw
payload bytes, signed payloads, archive contents, signing keys, or response
bodies as metric labels. The release smoke bundle should retain the telemetry
file hashes and aggregate pass/fail counts; the SF-11 gate rejects raw smoke
output in evidence.

### Binding-Generation Guide

`crates/sorafs_manifest/include/sorafs_reference.h` is the source contract for
native SDK bindings. Regenerate or review downstream bindings whenever that
header changes, and run `ci/check_sorafs_reference_ffi_header.sh` before
publishing. Each binding must pass byte slices and labels without changing
Norito bytes, must decode the returned `SorafsReferenceFfiBuffer` as
`ValidationOutcomeV1` JSON, and must release it with
`sorafs_reference_free_buffer`. Bindings must mirror the checked selector
constants for bundle, orderbook, repair, PoP, hedging, and proof-stream
profiles; unknown selector values should surface the returned
`ValidationOutcomeV1` error instead of mapping to local exceptions. Release
evidence for downstream packages must include package name/version, target
platform, exported selector inventory, package checksum, smoke result digest,
and the `release_manifest_digest_hex` it was built against.

## Packaging & Release
- Rust APIs currently ship through `sorafs_manifest::reference` and
  `sorafs_car`; a standalone Rust reference SDK package is not present in this
  workspace.
- `scripts/package_iroha_cli_release.sh` builds or packages
  `iroha` for the selected target, stages the checked
  `include/sorafs_reference.h` C header, runs committed-fixture smoke checks,
  writes binary, archive, and manifest SHA256 files, records staged-file,
  FFI-header, and smoke-output hashes in the manifest, and normalizes tar/gzip
  metadata for reproducible archive hashes. This helper is an unsigned
  artifact/checksum producer; it does not own a production signer or publish
  detached package-manifest signatures.
- The reference production path adds the package manifest and checksums to the
  canonical aggregate `release_manifest.json` after every target and rollout
  evidence input is final. `scripts/release_manifest_signing.py` authenticates
  the exact raw signature and independently reviewed public-key fingerprint
  through the SHA-256-pinned native `iroha app sorafs toolkit release-manifest` verifier.
  SF-11 additionally requires `release-manifest-receipt` to verify signer
  authority, independent attester and state-observer trust, current revocation
  state, and the exact finalized completion. Its independently pinned source
  context supplies all eight input identities, including the native executable;
  the caller supplies the trusted current clock separately. The daemon's
  purpose-bound producer retains a private immutable receipt before committing
  the operation and never retries signing during completed-operation recovery.
  Key storage is the operator's choice. The V1 result carries no backend,
  hardware-generation or exportability assertion; `signer_authority_verified`
  means the independently pinned authorization and receipt checks succeeded.
  Deployed signer and finalized-state adapters, plus coordinator integration,
  remain open; raw signature verification alone cannot close this release gate.
- The mandatory native release matrix is
  `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
  `x86_64-apple-darwin`, and `aarch64-apple-darwin`; the additional Windows
  artifact is `x86_64-pc-windows-msvc`. The release workflow builds and
  smoke-tests each binary on a runner whose Rust host exactly matches the target
  and refuses aggregate-manifest assembly unless exactly one checksum manifest
  exists for every target.
- Every remote GitHub Action in workflows and composite actions is pinned to a
  full 40-character commit SHA. `scripts/check_workflow_action_pins.py` enforces
  that repository-wide contract in both the dedicated workflow and the SoraFS
  release gate.
- Add every published archive or binary and its deterministic digest manifest
  to the final aggregate release inventory. Archive only the one authenticated
  aggregate-manifest signature tuple beside the hashes. Keep generated
  `dist/*` artifacts untracked and commit only `dist/.gitkeep`.
- Release notes template references new/changed validations and error codes.

## Release Evidence Gate

Operators should keep SF-11 release promotion fail-closed until payload-free
release evidence passes the checked-in gate:

```bash
python3 scripts/check_sorafs_reference_sdk_release_evidence.py \
  @scripts/examples/sorafs_reference_sdk_release_evidence.args.example
```

For reviewed collection planning, use the runner in dry-run mode before
executing it against captured evidence paths:

```bash
python3 scripts/run_sorafs_reference_sdk_release_evidence.py \
  @scripts/examples/sorafs_reference_sdk_release_collection.args.example \
  --dry-run
```

The checker recognizes `sorafs.reference_sdk.*` SF-11 release schemas for
release archives, signed manifests, per-target supply-chain results, downstream
bindings, cookbook smoke, FFI/header contract, and governance approval. Every
payload is schema-closed. It fails closed on stale evidence,
raw archive, binary, manifest, package, smoke-output, transaction, token,
secret, or private-key material, missing x86_64/aarch64 macOS and Linux release
targets, duplicate or unknown release-target entries, `target_count` values that do not
match the unique target list, missing binary/archive checksums, missing
deterministic-archive proof, tracked generated `dist/*` artifacts beyond
`dist/.gitkeep`, unsigned or unverified release manifests, missing governed
release-key fingerprints, unauthenticated signer authority, mismatched or
revoked completed operations, stale state observations, disclosed private keys, incomplete five-target binary
smoke/install/rollback/yank or
archive replay, missing per-target SBOMs, non-zero critical/high vulnerability
counts, missing OIDC identity or cosign provenance verification, missing
JavaScript/Python/Kotlin/JVM/Java Android/Swift/C# package publication evidence,
duplicate or unknown downstream-package entries, `package_count` values that do not match
the unique package list,
SDK export or `ValidationOutcomeV1` drift, missing native bridge/header binding,
failed published-archive cookbook smoke, missing fixture bundle or manifest/CAR
replay, non-integer or above-threshold smoke duration, FFI header drift, and
governance packets not bound to the governed release key roster, targets, downstream packages,
smoke evidence, and a `release_manifest_digest_hex` matching a valid signed
manifest artifact in the same bundle. Signed manifests also publish a
`policy_digest_hex`, governance approval must reference that same digest and
name the approved `public_key_fingerprint_hex`, and the gate summary emits
`valid_policy_digests` and `valid_release_key_fingerprints` only from valid
signed-manifest artifacts. Valid release-archive, supply-chain,
downstream-binding, cookbook-smoke, FFI/header-contract, and
governance-approval references now
publish their reviewed `release_manifest_digest_hex` values as
`valid_release_manifest_reference_digests`; the aggregate
production-readiness gate accepts those reference digests only as payload-free
metadata tethered to recognized artifact fingerprints. Signed-manifest artifacts
also fingerprint the reviewed `signature_algorithm`, the summary exports
`signature_algorithms`, and the aggregate production-readiness gate requires
that metadata to match the signed-manifest artifact fingerprint and stay inside
the governed Ed25519 release algorithm set before final promotion can report
ready. Aggregate promotion also rechecks the lane-proven reference SDK release
digest relationships: manifest-bound artifact fingerprints must match
`valid_release_manifest_digests`, and policy-bound artifact fingerprints must
match `valid_policy_digests`, and governance-approval release-key fingerprints
must match `valid_release_key_fingerprints` before final promotion can report
ready. The reference SDK release gate fail-closes when more than one valid
release manifest, policy, or release key anchor appears, and clears the mixed
`valid_release_manifest_digests`, `valid_policy_digests`, or
`valid_release_key_fingerprints` set before aggregate promotion can report
ready.
Release-manifest, policy, and release-key binding failures are recorded on the
offending artifact before required-kind validity is computed, so the JSON
summary matches the fail-closed release decision. The runner's dry-run plan
includes an `evidence_contract` map that operators can review before collecting
release evidence, and the runner validates the schema-closed collection-plan
envelope, required kinds, thresholds, external evidence map, evidence contract,
and command steps before dry-run output or verifier execution.
The shared runner plan guard also rejects non-canonical nested required-kind,
threshold, external-evidence, evidence-contract, and command-step shapes before
dry-run output or verifier execution. Narrowed
`--require-kind` release runs also reject evidence supplied for excluded kinds
before the plan is rendered or the verifier starts.
`scripts/build_sorafs_reference_sdk_release_canary.py` is the checked-in
payload-free SF-11 release evidence builder for reviewed release-archive,
signed-manifest, supply-chain, downstream-binding, cookbook-smoke,
FFI/header-contract, and governance-approval artifacts. It requires complete
target and downstream package coverage where applicable, reviewed
target/package inventories
closed to unknown values,
duplicate-free target/package inventories
whose count fields match their unique entries, release-manifest digest bindings,
positive integer threshold-reviewed smoke duration, and an independently
pinned signed-manifest source context. Signed-manifest policy, key, positive
revisions, and finalized operation anchors are derived only
from a freshly verified native operation receipt. Governance approval separately
requires policy and `--public-key-fingerprint-hex` inputs,
governed-release approval markers, and checker-backed validation before
atomically writing JSON without following output symlinks or output directories.
The SF-11 checker additionally requires the exact L1 topology summary and a
separately administered, domain-separated Ed25519 qualification envelope. The
operator trust tuple fixes the topology signer identity, positive key revision,
public-key fingerprint, policy digest, and review-age bound; unsigned, stale,
mutated, or provenance-key-reused topology inputs fail closed.

The four published source indexes and final lane summary remain payload-free.
Source-index assembly is a one-shot operation inside a protected, disposable
workspace. The builder uses descriptor-relative, no-follow access and
exclusive creation, then reopens and revalidates every generated file and
directory binding before success. On failure it closes its descriptors but
does not delete any generated name: portable POSIX deletion cannot be made
conditional on the inode identity that was created. Operators must discard the
entire failed workspace and retry in a fresh one; an in-place rerun rejects the
retained partial names. Safe automatic recovery remains a TODO for a future
reserved-namespace transaction/journal protocol.
For deterministic replay, the protected release workflow retains a separate
replay-complete source tree containing the public release archives, SBOM/SARIF
inputs, authenticated manifest tuple, aggregate GitHub attestation, per-file
cosign bundles, externally signed rehearsal/provenance receipts, and the signed
topology summary/envelope/trust tuple. Runtime credentials, private keys,
bearer tokens, and private evidence are never copied into that artifact.
The release-archive, signed-manifest, and supply-chain response-file examples are
`scripts/examples/sorafs_reference_sdk_release_archive_canary.args.example`,
`scripts/examples/sorafs_reference_sdk_release_signed_manifest_canary.args.example`,
and
`scripts/examples/sorafs_reference_sdk_release_supply_chain_canary.args.example`.

The release evidence scripts have focused Python coverage in:

- `scripts/tests/build_sorafs_reference_sdk_release_canary_test.py`
- `scripts/tests/check_sorafs_reference_sdk_release_evidence_test.py`
- `scripts/tests/run_sorafs_reference_sdk_release_evidence_test.py`

## Rollout Status
Implemented locally:
- Strict Node and Python SoraFS orderbook submit helpers now require a caller-signed canonical transaction, expected network context, and an expected Torii receipt signer before HTTP. Native ABI-29 inspectors enforce exact route/singleton/network/signature/owner bindings and derive the three authoritative identities; the response path accepts only one bounded `202 application/x-norito` receipt with all three exact raw-lowercase identity headers, verifies the pinned signer and receipt signature, and reports every post-dispatch failure as an ambiguous outcome that must be reconciled rather than retried. The source tests and required-symbol probes are wired into existing SDK lanes, but native artifacts have not been rebuilt or qualified.
- Reference validation APIs for adverts, admission envelopes, admission
  renewals/revocations, orders, signed orders, orderbook payloads, PoR, PDP,
  PoTR, repair, governance nodes, governance DAG blocks and signed-head chains,
  bundles, and manifest/CAR replay.
- `iroha` commands for validation and runtime signing, plus the
  `soranet_trustless_verifier --validation-outcome` manifest/CAR replay path.
- `reference_ffi` C ABI functions returning `ValidationOutcomeV1` Norito JSON,
  including orderbook payload selectors and bundle selectors for orderbook and
  PDP fixture members, with `crates/sorafs_manifest/include/sorafs_reference.h`
  and `ci/check_sorafs_reference_ffi_header.sh` providing the local binding
  contract guard.
- The test-only signed, schema-closed reference SDK inventory with 85 payload
  artifacts, 35 outcomes, 41 negative payload vectors, and twelve exact profiles,
  including the dedicated moderation governance-log-node validator and
  source-level coverage across JavaScript/TypeScript, Python, Swift,
  Kotlin/JVM, mirrored Java Android, and C#.
- Cookbook fixtures and smoke scripts under `fixtures/documentation/sorafs_reference_sdk/`.
- Release-packaging helper that stages binary/archive/manifest digests and
  unsigned package manifests under untracked
  `dist/iroha-release/`. It rejects retired per-package signature
  inputs. Authenticated signature and completed-operation receipt qualification
  apply to the final aggregate manifest after every target and evidence input
  is fixed; deployment and coordinator integration remain open.
- Published operator, metrics, and binding-generation guidance for packaging,
  telemetry extraction, C FFI header synchronization, downstream selector
  parity, and SF-11 release evidence handoff.
- Fail-closed SF-11 release evidence gate, collection planner with dry-run
  `evidence_contract` schema/field output, operator argfile templates, and
  focused tests for release archives, signed manifests, downstream bindings,
  cookbook smoke, FFI/header contract, and governance approval, including
  cross-artifact signed-manifest digest and policy-digest binding plus
  governance approval release-key fingerprint binding, aggregate-ready
  release-manifest reference digest metadata, and approved signed-manifest
  algorithm labels.

Remaining production gates:
- Build every required native artifact from one clean pinned commit for Linux
  x86_64, Linux aarch64, macOS x86_64, macOS aarch64, and Windows x86_64, then
  run all six SDK families' exact parity suites without capability-gated skips
  and publish only the authenticated resulting artifacts.
- Run the packaging helper for the supported release targets and publish signed
  release manifests outside the repository using governed release keys, then
  require those artifacts to pass the SF-11 release evidence gate.
- Ship/publish downstream SDK binding packages and release artifacts for the
  local JavaScript, Python, Kotlin/JVM, Java Android, Swift, and C# wrappers and
  attach their digests to the SF-11 downstream-bindings evidence packet.
- Archive live operator smoke evidence for the published `iroha`
  archives and cookbook replay before declaring SF-11 fully released, and
  require that evidence to pass the SF-11 gate.
