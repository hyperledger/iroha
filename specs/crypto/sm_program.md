//! SM2/SM3/SM4 enablement architecture brief for Hyperledger Iroha v2.

# SM Program Architecture Brief

## Purpose
Define the technical plan, supply-chain posture, and risk boundaries for introducing Chinese national cryptography (SM2/SM3/SM4) across the Iroha v2 stack while preserving deterministic execution and auditability.

## Scope
- **Consensus-critical paths:** `iroha_crypto`, `iroha`, `irohad`, IVM host, Kotodama intrinsics.
- **Client SDKs and tooling:** Rust CLI, Kagami, Python/JS/Swift SDKs, genesis utilities.
- **Configuration & serialization:** `iroha_config` knobs, Norito data model tags, manifest handling, multicodec updates.
- **Testing & compliance:** Unit/property/interop suites, Wycheproof harnesses, performance profiling, export/regulatory guidance. *(Status: RustCrypto-backed SM stack merged; optional `sm_proptest` fuzz suite and OpenSSL parity harness available for extended CI.)*

Out of scope: PQ algorithms, non-deterministic host acceleration in consensus paths; wasm/`no_std` builds are retired.

## Algorithm Inputs & Deliverables
| Artifact | Owner | Due | Notes |
|----------|-------|-----|-------|
| SM algorithm feature design (`SM-P0`) | Crypto WG | 2025-02 | Feature gating, dependency audit, risk register. |
| Core Rust integration (`SM-P1`) | Crypto WG / Data Model | 2025-03 | RustCrypto-based verify/hash/AEAD helpers, Norito extensions, fixtures. |
| Signing + VM syscalls (`SM-P2`) | IVM Core / SDK Program | 2025-04 | Deterministic signing wrappers, syscalls, Kotodama coverage. |
| Optional provider & ops enablement (`SM-P3`) | Platform Ops / Performance WG | 2025-06 | OpenSSL/Tongsuo backend, ARM intrinsics, telemetry, documentation. |

## Selected Libraries
- **Primary:** RustCrypto crates (`sm2`, `sm3`, `sm4`) with `rfc6979` feature enabled and SM3 bound to deterministic nonces.
- **Optional FFI:** OpenSSL 3.x provider API or Tongsuo for deployments requiring certified stacks or hardware engines; feature-gated and disabled by default in consensus binaries.

### Core Library Integration Status
- `iroha_crypto::sm` exposes SM3 hashing, SM2 verification, and SM4 GCM/CCM helpers under the unified `sm` feature, with deterministic RFC 6979 signing paths available to SDKs via `Sm2PrivateKey`.【crates/iroha_crypto/src/sm.rs:1049】【crates/iroha_crypto/src/sm.rs:1128】【crates/iroha_crypto/src/sm.rs:1236】
- Norito/Norito-JSON tags and multicodec helpers cover SM2 public keys/signatures and SM3/SM4 payloads so instructions serialize deterministically across hosts.【crates/iroha_data_model/src/isi/registry.rs:407】【crates/iroha_data_model/tests/sm_norito_roundtrip.rs:12】
- Known-answer suites validate the RustCrypto integration (`sm3_sm4_vectors.rs`, `sm2_negative_vectors.rs`) and run as part of CI’s `sm` feature jobs, keeping verification deterministic while nodes continue signing with Ed25519.【crates/iroha_crypto/tests/sm3_sm4_vectors.rs:15】【crates/iroha_crypto/tests/sm2_negative_vectors.rs:1】
- Optional `sm` feature build validation: `cargo check -p iroha_crypto --features sm --locked` (cold 7.9 s / warm 0.23 s) and `cargo check -p iroha_crypto --no-default-features --features sm --locked` (1.0 s) both succeed; enabling the feature adds 11 crates (`base64ct`, `ghash`, `opaque-debug`, `pem-rfc7468`, `pkcs8`, `polyval`, `primeorder`, `sm2`, `sm3`, `sm4`, `sm4-gcm`). Findings recorded in `specs/crypto/sm_rustcrypto_spike.md`.【specs/crypto/sm_rustcrypto_spike.md:1】
- BouncyCastle/GmSSL negative verification fixtures live under `crates/iroha_crypto/tests/fixtures/sm/sm2_negative_vectors.json`, ensuring canonical failure cases (r=0, s=0, distinguishing-ID mismatch, tampered public key) stay aligned with widely deployed providers.【crates/iroha_crypto/tests/sm2_negative_vectors.rs:1】【crates/iroha_crypto/tests/fixtures/sm/sm2_negative_vectors.json:1】
- `sm-ffi-openssl` now compiles the vendored OpenSSL 3.x toolchain (`openssl` crate `vendored` feature) so preview builds and tests always target a modern SM-capable provider even when system LibreSSL/OpenSSL lacks SM algorithms.【crates/iroha_crypto/Cargo.toml:59】
- `sm_accel` now detects AArch64 NEON at runtime and threads the SM3/SM4 hooks through x86_64/RISC-V dispatch while honouring the configuration knob `crypto.sm_intrinsics` (`auto`/`force-enable`/`force-disable`). When vector back-ends are absent the dispatcher still routes through the scalar RustCrypto path so benches and policy toggles behave consistently across hosts.【crates/iroha_crypto/src/sm.rs:702】【crates/iroha_crypto/src/sm.rs:733】

### Norito Schema & Data-Model Surfaces

| Norito type / consumer | Representation | Constraints & notes |
|------------------------|----------------|---------------------|
| `Sm3Digest` (`iroha_crypto::Sm3Digest`) | Bare: 32-byte blob · JSON: uppercase hex string (`"4F4D..."`) | Canonical Norito tuple wrapping `[u8; 32]`. JSON/Bare decoding rejects lengths ≠ 32. Round-trips covered by `sm_norito_roundtrip::sm3_digest_norito_roundtrip`. |
| `Sm2PublicKey` / `Sm2Signature` | Multicodec prefixed blobs (`0x1306` provisional) | Public keys encode uncompressed SEC1 points; signatures are `(r∥s)` (32 bytes each) with DER parsing guards. |
| `Sm4Key` | Bare: 16-byte blob | Zeroizing wrapper exposed to Kotodama/CLI. JSON serialization is deliberately omitted; operators should pass keys via blobs (contracts) or CLI hex (`--key-hex`). |
| `sm4_gcm_seal/open` operands | Tuple of 4 blobs: `(key, nonce, aad, payload)` | Key = 16 bytes; nonce = 12 bytes; tag length fixed at 16 bytes. Returns `(ciphertext, tag)`; Kotodama/CLI emit both hex and base64 helpers.【crates/ivm/tests/sm_syscalls.rs:728】 |
| `sm4_ccm_seal/open` operands | Tuple of 4 blobs (key, nonce, aad, payload) + tag length in `r14` | Nonce 7–13 bytes; tag length ∈ {4,6,8,10,12,14,16}. `sm` feature exposes CCM behind `sm-ccm` flag. |
| Kotodama intrinsics (`sm::hash`, `sm::seal_gcm`, `sm::open_gcm`, …) | Map to SCALLs above | Input validation mirrors host rules; malformed sizes raise `ExecutionError::Type`. |

Usage quick reference:
- **SM3 hashing in contracts/tests:** `Sm3Digest::hash(b"...")` (Rust) or Kotodama `sm::hash(input_blob)`. JSON expects 64 hex characters.
- **SM4 AEAD via CLI:** `iroha tools crypto sm4 gcm-seal --key-hex <32 hex> --nonce-hex <24 hex> --plaintext-hex …` yields hex/base64 ciphertext+tag pairs. Decrypt with matching `gcm-open`.
- **Multicodec strings:** SM2 public keys/signatures parse from/to the multibase string accepted by `PublicKey::from_str`/`Signature::from_bytes`, enabling Norito manifests and account IDs to carry SM signatories.

Data-model consumers should treat SM4 keys and tags as transient blobs; never persist raw keys on-chain. Contracts should store only ciphertext/tag outputs or derived digests (e.g., SM3 of the key) when auditing is required.

### Supply-Chain & Licensing
| Component | License | Mitigation |
|-----------|---------|-----------|
| `sm2`, `sm3`, `sm4` | Apache-2.0 / MIT | Track upstream commits, vendor if lockstep releases required, schedule third-party audit before validator signing GA. |
| `rfc6979` | Apache-2.0 / MIT | Already used in other algorithms; confirm deterministic `k` binding with SM3 digest. |
| Optional OpenSSL/Tongsuo | Apache-2.0 / BSD-style | Keep behind `sm-ffi-openssl` feature, require explicit operator opt-in and packaging checklist. |

### Feature Flags & Ownership
| Surface | Default | Maintainer | Notes |
|---------|---------|------------|-------|
| `iroha_crypto/sm-core`, `sm-ccm`, `sm` | Off | Crypto WG | Enables RustCrypto SM primitives; `sm` bundles CCM helpers for clients that require authenticated encryption. |
| IVM SM syscall surface | Always built | IVM Core Team | SM syscalls (`sm3_hash`, `sm2_verify`, `sm4_gcm_*`, `sm4_ccm_*`) are part of every first-release IVM build. Host policy derives from `crypto.allowed_signing` (presence of `sm2`). |
| `iroha_crypto/sm_proptest` | Off | QA / Crypto WG | Property-test harness covering malformed signatures/tags. Enabled only in extended CI. |
| `crypto.allowed_signing` + `default_hash` | `["ed25519"]`, `blake2b-256` | Config WG / Operators WG | Presence of `sm2` plus `sm3-256` hash enables SM syscalls/signatures; removing `sm2` returns to verify-only mode. |
| Optional `sm-ffi-openssl` (preview) | Off | Platform Ops | Placeholder feature for OpenSSL/Tongsuo provider integration; remains disabled until certification & packaging SOPs land. |

Network policy now exposes `network.require_sm_handshake_match` and
`network.require_sm_openssl_preview_match` (both default to `true`). For the
first release, both checks are mandatory: startup configuration normalizes to
strict matching, live `/v1/config` rejects attempts to clear either flag, and
the CLI only exposes the matching `--require-*` flags. This prevents accidental
divergence between SM-aware and SM-disabled peers.

#### OpenSSL/Tongsuo preview (`sm-ffi-openssl`)
- **Scope.** Builds a preview-only provider shim (`OpenSslProvider`) that validates OpenSSL runtime availability and exposes OpenSSL-backed SM3 hashing and SM4-GCM/CCM encrypt/decrypt while remaining opt-in. SM2 signing and verification always use the canonical portable SM2 relation.
- **Build prerequisites.** Compile with `cargo build -p iroha_crypto --features "sm sm-ffi-openssl"` and ensure the toolchain links against OpenSSL/Tongsuo 3.0+ (`libcrypto` with the required SM3/SM4 support; the negative ECDSA qualification test also requires the SM2 curve). Static linking is discouraged; prefer dynamic libraries managed by the operator.
- **Developer smoke test.** Run `scripts/sm_openssl_smoke.sh` to execute `cargo check -p iroha_crypto --features "sm sm-ffi-openssl"` followed by `cargo test -p iroha_crypto --features "sm sm-ffi-openssl" --test iroha_crypto_group_01 sm_openssl_smoke:: -- --nocapture`; the helper returns a nonzero prerequisite status when OpenSSL ≥ 3 development headers or `pkg-config` are unavailable, propagates build/test failures, and checks canonical SM2 verification with the preview enabled.
- **Rust scaffolding.** The `openssl_sm` module routes SM3 hashing and SM4 GCM/CCM operations through OpenSSL with structured errors covering preview toggles and invalid key/nonce/tag lengths. ECDSA on the SM2 curve is not SM2 and is not a supported signature verification path.
- **Prerequisite and failure status.** Missing OpenSSL ≥ 3.0 development files or `pkg-config` produces an explicit prerequisite diagnostic and exit status 2. Build and test failures retain their nonzero status; unavailable runtime capabilities remain open qualification gates, never a reported parity pass.
- **Runtime guardrails.** The OpenSSL preview is disabled by default; enable it via configuration (`crypto.enable_sm_openssl_preview` / `OpenSslProvider::set_preview_enabled(true)`) before attempting to use the FFI path. This flag selects only SM3/SM4 helpers. SM2 signing and verification use the canonical portable implementation, with `allowed_signing` controlling network admission independently.
- **Packaging checklist.** Document the provider version, installation path, and integrity hashes in deployment manifests. Operators must provide installation scripts that install the approved OpenSSL/Tongsuo build, register it with the OS trust store (if required), and pin upgrades behind maintenance windows.
- **Next steps.** Remaining milestones qualify the SM3/SM4 FFI paths, CI smoke jobs (see `ci/check_sm_openssl_stub.sh`), and telemetry. Track progress under SM-P3.1.x in `roadmap.md`.

#### Code Ownership Snapshot
- **Crypto WG:** `iroha_crypto`, SM fixtures, compliance documentation.
- **IVM Core:** syscall implementations, Kotodama intrinsics, host gating.
- **Config WG:** קונפיגורציית `crypto.allowed_signing`/`default_hash`, ולידציית מניפסט, חיווט קבלה.
- **SDK Program:** SM-aware tooling across CLI/Kagami/SDKs, shared fixtures.
- **Platform Ops & Performance WG:** acceleration hooks, telemetry, operator enablement.

## Configuration Migration Playbook

Operators moving from Ed25519-only networks to SM-enabled deployments should
follow the staged process in
[`sm_config_migration.md`](sm_config_migration.md). The guide covers build
validation, `iroha_config` layering (`defaults` → `user` → `actual`), genesis
regeneration via `kagami` overrides (for example `kagami genesis generate --allowed-signing sm2 --default-hash sm3-256`), pre-flight validation, and rollback
planning so configuration snapshots and manifests stay consistent across the
fleet.

## Deterministic Policy
- Enforce RFC6979-derived nonces for all SM2 signing paths in SDKs and optional host signing; verifiers accept canonical r∥s encodings only.
- Control-plane communication (streaming) remains Ed25519; SM2 limited to data-plane signatures unless governance approves expansion.
- Intrinsics (ARM SM3/SM4) restricted to deterministic verification/hash operations with runtime feature detection and software fallback.

## Norito & Encoding Plan
1. Extend algorithm enums in `iroha_data_model` with `Sm2PublicKey`, `Sm2Signature`, `Sm3Digest`, `Sm4Key`.
2. Serialize SM2 signatures as big-endian fixed-width `r∥s` arrays (32+32 bytes) to avoid DER ambiguities; conversions handled in adapters. *(Done: implemented in `Sm2Signature` helpers; Norito/JSON round-trips in place.)*
3. Register multicodec identifiers (`sm3-256`, `sm2-pub`, `sm4-key`) if using multiformats, update fixtures and docs. *(Progress: `sm2-pub` provisional code `0x1306` now validated with derived keys; SM3/SM4 codes pending final assignment, tracked via `sm_known_answers.toml`.)*
4. Update Norito golden tests covering roundtrips and rejection of malformed encodings (short/long r or s, invalid curve parameters).

## Host & VM Integration Plan (SM-2)
1. Implement host-side `sm3_hash` syscall mirroring the existing GOST hash shim; reuse `Sm3Digest::hash` and expose deterministic error paths. *(Landed: host returns Blob TLV; see `DefaultHost` implementation and `sm_syscalls.rs` regression.)*
2. Extend the VM syscall table with `sm2_verify` that accepts canonical r∥s signatures, validates distinguishing IDs, and maps failures to deterministic return codes. *(Done: host + Kotodama intrinsics return `1/0`; regression suite now covers truncated signatures, malformed public keys, non-blob TLVs, and UTF-8/empty/mismatched `distid` payloads.)*
3. Provide `sm4_gcm_seal`/`sm4_gcm_open` (and optionally CCM) syscalls with explicit nonce/tag sizing (RFC 8998). *(Done: GCM uses fixed 12-byte nonces + 16-byte tags; CCM supports 7–13 byte nonces with tag lengths {4,6,8,10,12,14,16} controlled via `r14`; Kotodama exposes these as `sm::seal_gcm/open_gcm` and `sm::seal_ccm/open_ccm`.) Document nonce reuse policy in the developer handbook.*
4. Wire Kotodama smoke contracts and IVM integration tests covering positive and negative cases (altered tags, malformed signatures, unsupported algorithms). *(Done via `crates/ivm/tests/kotodama_sm_syscalls.rs` mirroring host regressions for SM3/SM2/SM4.)*
5. Update syscall allowlists, policies, and ABI docs (`crates/ivm/docs/syscalls.md`) and refresh hashed manifests after adding the new entries.

### Host & VM Integration Status
- DefaultHost, CoreHost, and WsvHost expose the SM3/SM2/SM4 syscalls and gate them on `sm_enabled`, returning `PermissionDenied` when the runtime flag is false.【crates/ivm/src/host.rs:915】【crates/ivm/src/core_host.rs:833】【crates/ivm/src/mock_wsv.rs:2307】
- `crypto.allowed_signing` gating is threaded through pipeline/executor/state so production nodes opt in deterministically via configuration; adding `sm2` toggles SM helper availability.`【crates/iroha_core/src/smartcontracts/ivm/host.rs:170】【crates/iroha_core/src/state.rs:7673】【crates/iroha_core/src/executor.rs:683】
- Regression coverage exercises both enabled and disabled paths (DefaultHost/CoreHost/WsvHost) for SM3 hashing, SM2 verification, and SM4 GCM/CCM seal/open flows.【crates/ivm/tests/sm_syscalls.rs:129】【crates/ivm/tests/sm_syscalls.rs:733】【crates/ivm/tests/sm_syscalls.rs:1036】

## Configuration Threads
- Add `crypto.allowed_signing`, `crypto.default_hash`, `crypto.sm2_distid_default`, and the optional `crypto.enable_sm_openssl_preview` to `iroha_config`. Ensure data-model feature plumbing mirrors the crypto crate (`iroha_data_model` exposes `sm` → `iroha_crypto/sm`).
- Wire config to admission policies so manifests/genesis files define allowable algorithms; control-plane remains Ed25519 by default.

### CLI & SDK Work (SM-3)
1. **Torii CLI** (`crates/iroha_cli`): add SM2 keygen/import/export (distid aware), SM3 hashing helpers, and SM4 AEAD encrypt/decrypt commands. Update interactive prompts and docs.
2. **Genesis tooling** (`xtask`, `scripts/`): allow manifests to declare allowed signing algorithms and default hashes, fail fast if SM is enabled without corresponding config knobs. *(Done: `RawGenesisTransaction` now carries a `crypto` block with `default_hash`/`allowed_signing`/`sm2_distid_default`; `ManifestCrypto::validate` and `kagami genesis validate` reject inconsistent SM settings and defaults/genesis manifest advertises the snapshot.)*
3. **SDK surfaces**:
   - Rust (`iroha_client`): expose SM2 signing/verification helpers, SM3 hashing, SM4 AEAD wrappers with deterministic defaults.
   - Python/JS/Swift: mirror the Rust API; reuse staged fixtures in `sm_known_answers.toml` for cross-language tests.
4. Document operator workflow for enabling SM in CLI/SDK quickstarts and ensure JSON/YAML configs accept the new algorithm tags.

#### CLI progress
- `cargo run -p iroha_cli --features sm -- crypto sm2 keygen --distid CN12345678901234` now emits a JSON payload describing the SM2 key pair together with a `client.toml` snippet (`public_key_config`, `private_key_hex`, `distid`). The command accepts `--seed-hex` for deterministic generation and mirrors the RFC 6979 derivation used by hosts.
- `cargo xtask sm-operator-snippet --distid CN12345678901234` wraps the keygen/export flow, writing the same `sm2-key.json`/`client-sm2.toml` outputs in one step. Use `--json-out <path|->` / `--snippet-out <path|->` to redirect files or stream them to stdout, removing the `jq` dependency for automation.
- `iroha_cli tools crypto sm2 import --private-key-hex <hex> [--distid ...]` derives the same metadata from existing material so operators can validate distinguishing IDs before admission.
- `iroha_cli tools crypto sm2 export --private-key-hex <hex> --emit-json` prints the config snippet (including `allowed_signing`/`sm2_distid_default` guidance) and optionally re-emits the JSON key inventory for scripting.
- `iroha_cli tools crypto sm3 hash --data <string>` hashes arbitrary payloads; `--data-hex` / `--file` cover binary inputs and the command reports both hex and base64 digests for manifest tooling.
- `iroha_cli tools crypto sm4 gcm-seal --key-hex <KEY> --nonce-hex <NONCE> --plaintext-hex <PT>` (and `gcm-open`) wrap the host SM4-GCM helpers and surface `ciphertext_hex`/`tag_hex` or plaintext payloads. `sm4 ccm-seal` / `sm4 ccm-open` provide the same UX for CCM with nonce length (7–13 bytes) and tag length (4,6,8,10,12,14,16) validation baked in; both commands optionally emit raw bytes to disk.

## Testing Strategy
### Unit/Known Answer Tests
- GM/T 0004 & GB/T 32905 vectors for SM3 (e.g., `"abc"`).
- GM/T 0002 & RFC 8998 vectors for SM4 (block + GCM/CCM).
- GM/T 0003/GB/T 32918 examples for SM2 (Z-value, signature verification), including Annex Example 1 with ID `ALICE123@YAHOO.COM`.
- Interim fixture staging file: `crates/iroha_crypto/tests/fixtures/sm_known_answers.toml`.
- Wycheproof-derived SM2 regression suite (`crates/iroha_crypto/tests/sm2_wycheproof.rs`) now carries a 52-case corpus that layers deterministic fixtures (Annex D, SDK seeds) with bit-flip, message-tamper, and truncated-signature negatives. The sanitized JSON lives in `crates/iroha_crypto/tests/fixtures/wycheproof_sm2.json`, and `sm2_fuzz.rs` consumes it directly so both happy-path and tamper scenarios stay aligned across fuzz/property runs. 벡터들은 표준 곡선뿐만 아니라 Annex 영역도 다루며, 필요 시 내장 `Sm2PublicKey` 검증 이후 BigInt 백업 루틴이 추적을 완료합니다.
- `cargo xtask sm-wycheproof-sync --input <wycheproof-sm2.json>` (or `--input-url <https://…>`) deterministically trims any upstream drop (generator tag optional) and rewrites `crates/iroha_crypto/tests/fixtures/wycheproof_sm2.json`. Until C2SP publishes the official corpus, download forks manually and feed them through the helper; it normalises keys, counts, and flags so reviewers can reason over diffs.
- SM2/SM3 Norito round-trips validated in `crates/iroha_data_model/tests/sm_norito_roundtrip.rs`.
- SM3 host syscall regression in `crates/ivm/tests/sm_syscalls.rs` (SM feature).
- SM2 verify syscall regression in `crates/ivm/tests/sm_syscalls.rs` (success + failure cases).

### Property & Regression Tests
- Proptest for SM2 rejecting invalid curves, non-canonical r/s, and reuse of nonces. *(Available in `crates/iroha_crypto/tests/sm2_fuzz.rs`, gated behind `sm_proptest`; enable via `cargo test -p iroha_crypto --features "sm sm_proptest"`.)*
- Wycheproof SM4 vectors (block/AES-mode) adapted for varied modes; track upstream for SM2 additions. `sm3_sm4_vectors.rs` now exercises tag bit-flips, truncated tags, and ciphertext tampering for both GCM and CCM.

### Interop & Performance
- RustCrypto ↔ OpenSSL/Tongsuo parity suite for SM2 sign/verify, SM3 digests, and SM4 ECB/GCM lives in `crates/iroha_crypto/tests/sm_cli_matrix.rs`; invoke it with `scripts/sm_interop_matrix.sh`. CCM parity vectors now run in `sm3_sm4_vectors.rs`; CLI matrix support will follow once upstream CLIs expose CCM helpers.
- SM3 NEON helper now runs the Armv8 compression/padding path end-to-end with runtime gating through `sm_accel::is_sm3_enabled` (feature + env overrides mirrored across SM3/SM4). Golden digests (zero/`"abc"`/long-block + randomized lengths) and forced-disable tests keep parity with the scalar RustCrypto backend, and the Criterion micro-bench (`crates/sm3_neon/benches/digest.rs`) captures scalar vs NEON throughput on AArch64 hosts.
- Perf harness mirroring `scripts/gost_bench.sh` to compare Ed25519/SHA-2 vs SM2/SM3/SM4 and validate tolerance thresholds.

#### Arm64 Baseline (local Apple Silicon; Criterion `sm_perf`, refreshed 2025-12-05)
- `scripts/sm_perf.sh` now runs the Criterion bench and enforces medians against `crates/iroha_crypto/benches/sm_perf_baseline.json` (recorded on aarch64 macOS; tolerance 25 % by default, baseline metadata captures the host triple). The new `--mode` flag lets engineers capture scalar vs NEON vs `sm-neon-force` datapoints without editing the script; the current capture bundle (raw JSON + aggregated summary) lives under `artifacts/sm_perf/2026-03-lab/m3pro_native/` and stamps every payload with `cpu_label="m3-pro-native"`.
- Acceleration modes now auto-select the scalar baseline as a comparison target. `scripts/sm_perf.sh` threads `--compare-baseline/--compare-tolerance/--compare-label` through `sm_perf_check`, emitting per-benchmark deltas against the scalar reference and failing when the slowdown exceeds the configured threshold. Per-benchmark tolerances from the baseline drive the comparison guard (SM3 is capped at 12 % on the Apple scalar baseline, while the SM3 comparison delta now permits up to 70 % against the scalar reference to avoid flapping); the Linux baselines reuse the same comparison map because they are exported from the `neoverse-proxy-macos` capture, and we will tighten them after a bare-metal Neoverse run if the medians differ. Pass `--compare-tolerance` explicitly when capturing stricter bounds (e.g., `--compare-tolerance 0.20`) and use `--compare-label` to annotate alternative reference hosts.
- Baselines recorded on the CI reference machine now live in `crates/iroha_crypto/benches/sm_perf_baseline_aarch64_macos_scalar.json`, `sm_perf_baseline_aarch64_macos_auto.json`, and `sm_perf_baseline_aarch64_macos_neon_force.json`. Refresh them with `scripts/sm_perf.sh --mode scalar --write-baseline`, `--mode auto --write-baseline`, or `--mode neon-force --write-baseline` (set `SM_PERF_CPU_LABEL` before capturing) and archive the generated JSON alongside the run logs. Keep the aggregated helper output (`artifacts/.../aggregated.json`) with the PR so reviewers can audit every sample. Linux/Neoverse baselines now ship in `sm_perf_baseline_aarch64_unknown_linux_gnu_{mode}.json`, promoted from `artifacts/sm_perf/2026-03-lab/neoverse-proxy-macos/aggregated.json` (CPU label `neoverse-proxy-macos`, SM3 compare tolerance 0.70 for aarch64 macOS/Linux); rerun on bare-metal Neoverse hosts when available to tighten the tolerances.
- Baseline JSON files may now carry an optional `tolerances` object to tighten guardrails per benchmark. Example:
  ```json
  {
    "benchmarks": { "...": 12.34 },
    "tolerances": {
      "sm4_vs_chacha20poly1305_encrypt/sm4_gcm_encrypt": 0.08,
      "sm3_vs_sha256_hash/sm3_hash": 0.12
    }
  }
  ```
  `sm_perf_check` applies these fractional limits (8 % and 12 % in the example) while using the global CLI tolerance for any benchmarks not listed.
- Comparison guards can also honour `compare_tolerances` in the comparison baseline. Use this to allow a looser delta against the scalar reference (for example, `\"sm3_vs_sha256_hash/sm3_hash\": 0.70` in the scalar baseline) while keeping the primary `tolerances` strict for direct baseline checks.
- The checked-in Apple Silicon baselines now ship with concrete guardrails: SM2/SM4 operations allow 12–20 % drift depending on variance, while SM3/ChaCha comparisons sit at 8–12 %. The scalar baseline’s `sm3` tolerance is now tightened to 0.12; the `unknown_linux_gnu` files mirror the `neoverse-proxy-macos` export with the same tolerance map (SM3 compare 0.70) and metadata notes indicating they are shipped for the Linux gate until a bare-metal Neoverse rerun is available.
- SM2 signing: 298 µs per op (Ed25519: 32 µs) ⇒ ~9.2× slower; verification: 267 µs (Ed25519: 41 µs) ⇒ ~6.5× slower.
- SM3 hashing (4 KiB payload): 11.2 µs, effectively parity with SHA-256 at 11.3 µs (≈356 MiB/s vs 353 MiB/s).
- SM4-GCM seal/open (1 KiB payload, 12-byte nonce): 15.5 µs vs ChaCha20-Poly1305 at 1.78 µs (≈64 MiB/s vs 525 MiB/s).
- Benchmark artefacts (`target/criterion/sm_perf*`) captured for reproducibility; the Linux baselines are sourced from `artifacts/sm_perf/2026-03-lab/neoverse-proxy-macos/` (CPU label `neoverse-proxy-macos`, SM3 compare tolerance 0.70) and can be refreshed on bare-metal Neoverse hosts (`SM-4c.1`) once lab time opens to tighten tolerances.

#### Cross-architecture capture checklist
- Run `scripts/sm_perf_capture_helper.sh` **on the target machine** (x86_64 workstation, Neoverse ARM server, etc.). Pass `--cpu-label <host>` to stamp the captures and (when running in matrix mode) to pre-populate the generated plan/commands for lab scheduling. The helper prints mode-specific commands that:
  1. execute the Criterion suite with the correct feature set, and
  2. write medians into `crates/iroha_crypto/benches/sm_perf_baseline_${arch}_${os}_${mode}.json`.
- Capture the scalar baseline first, then re-run the helper for `auto` (and `neon-force` on AArch64 platforms). Use a meaningful `SM_PERF_CPU_LABEL` so reviewers can trace host details in the JSON metadata.
- After each run, archive the raw `target/criterion/sm_perf*` directory and include it in the PR together with the generated baselines. Tighten per-benchmark tolerances as soon as two consecutive runs stabilise (see `sm_perf_baseline_aarch64_macos_*.json` for reference formatting).
- Record the medians + tolerances in this section and update `status.md`/`roadmap.md` when a new architecture is covered. The Linux baselines are now checked in from the `neoverse-proxy-macos` capture (metadata notes the export to the aarch64-unknown-linux-gnu gate); rerun on bare-metal Neoverse/x86_64 hosts as follow-ups when those lab slots are available.

#### ARMv8 SM3/SM4 intrinsics vs scalar paths
`sm_accel` (see `crates/iroha_crypto/src/sm.rs:739`) provides the runtime dispatch layer for NEON-backed SM3/SM4 helpers. The feature is guarded at three levels:

| Layer | Control | Notes |
|-------|---------|-------|
| Compile time | `--features sm` (now pulls in `sm-neon` automatically on `aarch64`) or `sm-neon-force` (tests/benchmarks) | Builds the NEON modules and links `sm3-neon`/`sm4-neon`; the forced feature makes `auto` behave like `force-enable` but an explicit `force-disable` policy still pins the scalar fallback. |
| Runtime auto-detect | `sm4_neon::is_supported()` | Only true on CPUs that expose AES/PMULL equivalents (e.g., Apple M-series, Neoverse V1/N2). VMs that mask NEON or FEAT_SM4 fall back to scalar code. |
| Operator override | `crypto.sm_intrinsics` (`auto`/`force-enable`/`force-disable`) | Config-driven dispatch applied at startup; use `force-enable` only for profiling in trusted environments and prefer `force-disable` when validating scalar fallbacks. |

**Performance envelope (Apple M3 Pro; medians recorded in `sm_perf_baseline_aarch64_macos_{mode}.json`):**

| Mode | SM3 digest (4 KiB) | SM4-GCM seal (1 KiB) | Notes |
|------|-------------------|----------------------|-------|
| Scalar | 11.6 µs | 15.9 µs | Deterministic RustCrypto path; used everywhere the `sm` feature is compiled but NEON is unavailable. |
| NEON auto | ~2.7× faster than scalar | ~2.3× faster than scalar | Current NEON kernels (SM-5a.2c) widen the schedule four words at a time and use dual queue fan-out; exact medians vary per host, so consult the baseline JSON metadata. |
| NEON force | Mirrors NEON auto unless `force-disable` is configured | Same as NEON auto | Exercised via `scripts/sm_perf.sh --mode neon-force`; keeps CI honest even on hosts that would default to scalar mode while preserving the scalar fallback escape hatch. |

**Determinism & deployment guidance**
- Intrinsics never change observable results—`sm_accel` returns `None` when the accelerated path is unavailable so the scalar helper runs. Consensus code paths therefore remain deterministic as long as the scalar implementation is correct.
- Do **not** gate business logic on whether the NEON path was used. Treat the acceleration purely as a perf hint and expose the status via telemetry only (e.g., `sm_intrinsics_enabled` gauge).
- Always run `ci/check_sm_perf.sh` (or `make check-sm-perf`) after touching SM code so the Criterion harness validates both scalar and accelerated paths using the tolerances embedded in each baseline JSON.
- When benchmarking or debugging, prefer the config knob `crypto.sm_intrinsics` over compile-time flags; recompiling with `sm-neon-force` changes the `auto` default to forced acceleration, whereas `force-disable` remains the explicit scalar fallback path.
- Document the chosen policy in release notes: production builds should leave the policy in `Auto`, letting each validator discover hardware capabilities independently while still sharing the same binary artefacts.
- Avoid shipping binaries that mix statically linked vendor intrinsics (e.g., third-party SM4 libraries) unless they respect the same dispatch and testing flow—otherwise perf regressions will not be caught by our baseline tooling.

#### x86_64 Rosetta baseline (Apple M3 Pro; captured 2025-12-01)
- Baselines live in `crates/iroha_crypto/benches/sm_perf_baseline_x86_64_macos_{scalar,auto,neon_force}.json` (cpu_label=`m3-pro-rosetta`), with raw + aggregated captures under `artifacts/sm_perf/2026-03-lab/m3pro_rosetta/`.
- Per-benchmark tolerances on x86_64 are set to 20 % for SM2, 15 % for Ed25519/SHA-256, and 12 % for SM4/ChaCha. `scripts/sm_perf.sh` now defaults the acceleration comparison tolerance to 25 % on non-AArch64 hosts so scalar-vs-auto stays tight while leaving the 5.25 slack on AArch64 for the shared `m3-pro-native` baseline until a Neoverse rerun lands.

| Benchmark | Scalar | Auto | Neon-Force | Auto vs Scalar | Neon vs Scalar | Neon vs Auto |
|-----------|--------|------|------------|----------------|---------------|--------------|
| sm2_vs_ed25519_sign/ed25519_sign |    57.43 |  57.12 |      55.77 |          -0.53% |         -2.88% |        -2.36% |
| sm2_vs_ed25519_sign/sm2_sign |   572.76 | 568.71 |     557.83 |          -0.71% |         -2.61% |        -1.91% |
| sm2_vs_ed25519_verify/verify/ed25519 |    69.03 |  68.42 |      66.28 |          -0.88% |         -3.97% |        -3.12% |
| sm2_vs_ed25519_verify/verify/sm2 |   521.73 | 514.50 |     502.17 |          -1.38% |         -3.75% |        -2.40% |
| sm3_vs_sha256_hash/sha256_hash |    16.78 |  16.58 |      16.16 |          -1.19% |         -3.69% |        -2.52% |
| sm3_vs_sha256_hash/sm3_hash |    15.78 |  15.51 |      15.04 |          -1.71% |         -4.69% |        -3.03% |
| sm4_vs_chacha20poly1305_decrypt/chacha20poly1305_decrypt |     1.96 |   1.97 |       1.97 |           0.39% |          0.16% |        -0.23% |
| sm4_vs_chacha20poly1305_decrypt/sm4_gcm_decrypt |    16.26 |  16.38 |      16.26 |           0.72% |         -0.01% |        -0.72% |
| sm4_vs_chacha20poly1305_encrypt/chacha20poly1305_encrypt |     1.96 |   2.00 |       1.93 |           2.23% |         -1.14% |        -3.30% |
| sm4_vs_chacha20poly1305_encrypt/sm4_gcm_encrypt |    16.60 |  16.58 |      16.15 |          -0.10% |         -2.66% |        -2.57% |

#### x86_64 / other non-aarch64 targets
- Current builds still ship only the deterministic RustCrypto scalar path on x86_64; keep `sm` enabled but do **not** inject external AVX2/VAES kernels until SM-4c.1b lands. Runtime policy mirrors ARM: default to `Auto`, honour `crypto.sm_intrinsics`, and surface the same telemetry gauges.
- Linux/x86_64 captures remain to be recorded; reuse the helper on that hardware and drop the medians into `sm_perf_baseline_x86_64_unknown_linux_gnu_{mode}.json` alongside the Rosetta baselines and tolerance map above.

**Common pitfalls**
1. **Virtualised ARM instances:** Many clouds expose NEON but hide the SM4/AES extensions that `sm4_neon::is_supported()` checks. Expect the scalar path in those environments and capture perf baselines accordingly.
2. **Partial overrides:** Mixing persisted `crypto.sm_intrinsics` values between runs leads to inconsistent perf readings. Document the intended override in the experiment ticket and reset the config before capturing new baselines.
3. **CI parity:** Some macOS runners do not allow counter-based perf sampling while NEON is active. Keep `scripts/sm_perf_capture_helper.sh` outputs attached to PRs so reviewers can confirm that the accelerated path was exercised even if the runner hides those counters.
4. **Future ISA variants (SVE/SVE2):** The current kernels assume NEON lane shapes. Before porting to SVE/SVE2, extend `sm_accel::NeonPolicy` with a dedicated variant so we can keep CI, telemetry, and operator knobs aligned.

Action items tracked under SM-5a/SM-4c.1 ensure that CI captures parity proofs for every new architecture, and the roadmap stays at 🈺 until Neoverse/x86 baselines and NEON-vs-scalar tolerances converge.

## Compliance & Regulatory Notes

### Standards & Normative References
- **GM/T 0002-2012** (SM4), **GM/T 0003-2012** + **GB/T 32918 series** (SM2), **GM/T 0004-2012** + **GB/T 32905/32907** (SM3), and **RFC 8998** govern the algorithm definitions, test vectors, and KDF bindings that our fixtures consume.【specs/crypto/sm_vectors.md#L79】
- The compliance brief in `specs/crypto/sm_compliance_brief.md` cross-links these standards alongside the filing/export responsibilities for engineering, SRE, and legal teams; keep that brief updated whenever the GM/T catalog revises.

### Mainland China Regulatory Workflow
1. **Product filing (开发备案):** Prior to shipping SM-enabled binaries from mainland China, submit the artifact manifest, deterministic build steps, and dependency list to the provincial cryptography administration. Filing templates and the compliance checklist live in `specs/crypto/sm_compliance_brief.md` and the attachments directory (`sm_product_filing_template.md`, `sm_sales_usage_filing_template.md`, `sm_export_statement_template.md`).
2. **Sales/Usage filing (销售/使用备案):** Operators running SM-enabled nodes onshore must register their deployment scope, key management posture, and telemetry plan. Attach signed manifests plus `iroha_sm_*` metric snapshots when filing.
3. **Accredited testing:** Critical infrastructure operators may require certified lab reports. Provide reproducible build scripts, SBOM exports, and the Wycheproof/interop artefacts (see below) so downstream auditors can reproduce the vectors without altering the code.
4. **Status tracking:** Record completed filings in the release ticket and `status.md`; missing filings block promotion from verify-only to signing pilots.

### Export & Distribution Posture
- Treat SM-capable binaries as controlled items under **US EAR Category 5 Part 2** and **EU Regulation 2021/821 Annex 1 (5D002)**. Publication of source continues to qualify for the open-source/ENC carve-outs, but redistribution to embargoed destinations still requires legal review.
- Release manifests must bundle an export statement referencing the ENC/TSU basis and list the OpenSSL/Tongsuo build identifiers if the FFI preview is packaged.
- Prefer region-local packaging (e.g., mainland mirrors) when operators need onshore distribution to avoid cross-border transfer issues.

### Operator Documentation & Evidence
- Pair this architecture brief with the rollout checklist in `specs/crypto/sm_operator_rollout.md` and the compliance filing guide in `specs/crypto/sm_compliance_brief.md`.
- Keep code-adjacent genesis specifications and examples aligned with the
  implementation. Maintain the
  [public genesis reference](https://docs.iroha.tech/reference/genesis.html)
  and operator guidance in the sibling `iroha-docs` repository.
- Archive OpenSSL/Tongsuo provenance, `scripts/sm_openssl_smoke.sh` output, and `scripts/sm_interop_matrix.sh` parity logs with every release bundle so compliance and audit partners have deterministic artefacts.
- Update `status.md` whenever compliance scope changes (new jurisdictions, filing completions, or export decisions) to keep programme state discoverable.
- Follow the staged readiness reviews (`SM-RR1`–`SM-RR3`) captured in `specs/release_runbook.md`; promotion between verify-only, pilot, and GA signing phases requires the artefacts enumerated there.

## Interop Recipes

### RustCrypto ↔ OpenSSL/Tongsuo Matrix
1. Ensure OpenSSL/Tongsuo CLIs are available (`IROHA_SM_CLI="openssl /opt/tongsuo/bin/openssl"` allows explicit tool selection).
2. Run `scripts/sm_interop_matrix.sh`; it invokes `cargo test -p iroha_crypto --test sm_cli_matrix --features sm` and exercises SM2 sign/verify, SM3 digests, and SM4 ECB/GCM flows against each provider, skipping any CLI that is absent.【scripts/sm_interop_matrix.sh#L1】
3. Archive the resulting `target/debug/deps/sm_cli_matrix*.log` files with the release artefacts.

### OpenSSL Preview Smoke (Packaging Gate)
1. Install OpenSSL ≥ 3.0 development headers and ensure `pkg-config` can locate them.
2. Execute `scripts/sm_openssl_smoke.sh`; the helper runs `cargo check`/`cargo test --test iroha_crypto_group_01 sm_openssl_smoke::`, exercising SM3 hashing and SM4-GCM round-trips via the FFI backend plus canonical SM2 verification with the preview enabled (the test harness enables the preview explicitly).【scripts/sm_openssl_smoke.sh#L1】
3. Keep this release gate open until required prerequisites and runtime capabilities are present and the exact candidate checks pass. Capture nonzero failures and unavailable-capability diagnostics as open gates, together with the successful SM3/SM4 and canonical SM2 evidence.

### Deterministic Fixture Refresh
- Regenerate SM fixtures (`sm_vectors.md`, `fixtures/sm/…`) before each compliance filing, then re-run the parity matrix and smoke harness so auditors receive fresh deterministic transcripts alongside the filings.

## External Audit Preparation
- `specs/crypto/sm_audit_brief.md` packages the context, scope, schedule, and contacts for the external review.
- Audit artefacts live under `specs/crypto/attachments/` (OpenSSL smoke log, cargo tree snapshot, cargo metadata export, toolkit provenance) and `fuzz/sm_corpus_manifest.json` (deterministic SM fuzz seeds sourced from existing regression vectors). On macOS the smoke log currently records a skipped run because the workspace dependency cycle prevents `cargo check`; Linux builds without the cycle will exercise the preview backend fully.
- Circulated to Crypto WG, Platform Ops, Security, and Docs/DevRel leads on 2026-01-30 for alignment ahead of RFQ dispatch.

### Audit Engagement Status

- **Trail of Bits (CN cryptography practice)** — Statement of Work executed on **2026-02-21**, kick-off **2026-02-24**, fieldwork window **2026-02-24 – 2026-03-22**, final report due **2026-04-15**. Weekly status checkpoint every Wednesday 09:00 UTC with the Crypto WG lead and Security Engineering liaison. See [`sm_audit_brief.md`](sm_audit_brief.md#engagement-status) for contacts, deliverables, and evidence attachments.
- **NCC Group APAC (contingency slot)** — Reserved the May 2026 window as a follow-up/parallel review should additional findings or regulator requests require a second opinion. Engagement details and escalation hooks are recorded alongside the Trail of Bits entry in `sm_audit_brief.md`.

## Risks & Mitigations

Full register: see [`sm_risk_register.md`](sm_risk_register.md) for detailed
probability/impact scoring, monitoring triggers, and sign-off history. The
summary below tracks the headline items surfaced to release engineering.
| Risk | Severity | Owner | Mitigation |
|------|----------|-------|------------|
| Lack of external audit for RustCrypto SM crates | High | Crypto WG | Contract Trail of Bits/NCC Group, keep verify-only until audit report accepted. |
| Deterministic nonce regressions across SDKs | High | SDK Program Leads | Share fixtures across SDK CI; enforce canonical r∥s encoding; add cross-SDK integration tests (tracked in SM-3c). |
| ISA-specific bugs in intrinsics | Medium | Performance WG | Feature-gate intrinsics, require CI coverage on ARM, maintain software fallback. Hardware validation matrix maintained in `sm_perf.md`. |
| Compliance ambiguity delaying adoption | Medium | Docs & Legal Liaison | Publish compliance brief & operator checklist (SM-6a/SM-6b) before GA; gather legal input. Filing checklist shipped in `sm_compliance_brief.md`. |
| FFI backend drift with provider updates | Medium | Platform Ops | Pin provider versions, add parity tests, keep FFI backend opt-in until packaging stabilises (SM-P3). |

## Open Questions / Follow-ups
1. Select independent audit partners experienced with SM algorithms in Rust.
   - **Answer (2026-02-24):** Trail of Bits’ CN cryptography practice signed the primary audit SOW (kick-off 2026-02-24, delivery 2026-04-15) and NCC Group APAC holds a May contingency slot so regulators can request a second review without reopening procurement. Engagement scope, contacts, and checklists live in [`sm_audit_brief.md`](sm_audit_brief.md#engagement-status) and are mirrored in `sm_audit_vendor_landscape.md`.
2. Continue tracking upstream for an official Wycheproof SM2 dataset; the workspace currently ships a curated 52-case suite (deterministic fixtures + synthesized tamper cases) and feeds it into `sm2_wycheproof.rs`/`sm2_fuzz.rs`. Update the corpus via `cargo xtask sm-wycheproof-sync` once the upstream JSON lands.
   - Track Bouncy Castle and GmSSL negative vector suites; import into `sm2_fuzz.rs` once licensing cleared to supplement the existing corpus.
3. Define baseline telemetry (metrics, logging) for SM adoption monitoring.
4. Decide whether SM4 AEAD default is GCM or CCM for Kotodama/VM exposure.
5. Track RustCrypto/OpenSSL parity for Annex Example 1 (ID `ALICE123@YAHOO.COM`): confirm library support for the published public key and `(r, s)` so fixtures can be promoted to regression tests.

## Action Items
- [x] Finalise dependency audit and capture in the security tracker.
- [x] Confirm audit partner engagement for the RustCrypto SM crates (SM-P0 follow-up). Trail of Bits (CN cryptography practice) owns the primary review with kickoff/delivery dates recorded in `sm_audit_brief.md`, and NCC Group APAC retained a May 2026 contingency slot to satisfy regulator or governance follow-ups.
- [x] Extend Wycheproof coverage for SM4 CCM tamper cases (SM-4a).
- [x] Land canonical SM2 signing fixtures across SDKs and wire into CI (SM-3c/SM-1b.1); guarded by `scripts/check_sm2_sdk_fixtures.py` (see `ci/check_sm2_sdk_fixtures.sh`).

## Compliance Appendix (State Commercial Cryptography)

- **Classification:** SM2/SM3/SM4 ship under China’s *state commercial cryptography* regime (PRC Cryptography Law, Art. 3). Shipping these algorithms in Iroha software does **not** place the project in the core/common (state-secret) tiers, but operators using them in PRC deployments must follow commercial-crypto filing and MLPS obligations.【specs/crypto/sm_chinese_crypto_law_brief.md:14】
- **Standards lineage:** Align public documentation in the sibling `iroha-docs`
  repository with the official GB/T conversions of the GM/T specs:

| Algorithm | GB/T reference | GM/T origin | Notes |
|-----------|----------------|-------------|-------|
| SM2 | GB/T 32918 (all parts) | GM/T 0003 | ECC digital signature + key exchange; Iroha exposes verification in core nodes and deterministic signing to SDKs. |
| SM3 | GB/T 32905 | GM/T 0004 | 256-bit hash; deterministic hashing across scalar and ARMv8 accelerated paths. |
| SM4 | GB/T 32907 | GM/T 0002 | 128-bit block cipher; Iroha provides GCM/CCM helpers and ensures big-endian parity across implementations. |

- **Capability manifest:** The Torii `/v1/node/capabilities` endpoint advertises the following JSON shape so operators and tooling can consume the SM manifest programmatically:

```json
{
  "abi_version": 1,
  "data_model_version": 4,
  "crypto": {
    "sm": {
      "enabled": true,
      "default_hash": "sm3-256",
      "allowed_signing": ["ed25519"],
      "sm2_distid_default": "1234567812345678",
      "openssl_preview": false,
      "acceleration": {
        "scalar": true,
        "neon_sm3": false,
        "neon_sm4": false,
        "policy": "auto"
      }
    }
  }
}
```

The CLI subcommand `iroha runtime capabilities` surfaces the same payload locally, printing a one-line summary alongside the JSON advert for compliance evidence collection.

- **Documentation deliverables:** publish release notes and SBOMs that identify the algorithms/standards above, and keep the full compliance brief (`sm_chinese_crypto_law_brief.md`) bundled with release artefacts so operators can attach it to provincial filings.【specs/crypto/sm_chinese_crypto_law_brief.md:59】
- **Operator hand-off:** remind deployers that MLPS 2.0/GB/T 39786-2021 require crypto application assessments, SM key-management SOPs, and ≥ 6 year evidence retention; point them to the operator checklist in the compliance brief.【specs/crypto/sm_chinese_crypto_law_brief.md:43】【specs/crypto/sm_chinese_crypto_law_brief.md:74】

## Communication Plan
- **Audience:** Crypto WG core members, Release Engineering, Security Review board, SDK program leads.
- **Artifacts:** `sm_program.md`, `sm_lock_refresh_plan.md`, `sm_vectors.md`, `sm_wg_sync_template.md`, roadmap excerpt (SM-0 .. SM-7a).
- **Channel:** Weekly Crypto WG sync agenda + follow-up email summarising action items and requesting approval for lock refresh and dependency intake (draft circulated 2025-01-19).
- **Owner:** Crypto WG lead (delegate acceptable).
