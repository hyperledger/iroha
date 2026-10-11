# Hyperledger Iroha

[![GitHub License](https://img.shields.io/github/license/hyperledger-iroha/iroha)](./LICENSE)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/960/badge)](https://www.bestpractices.dev/projects/960)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/hyperledger/iroha/badge)](https://scorecard.dev/viewer/?uri=github.com/hyperledger/iroha)

Hyperledger Iroha 3 is a deterministic blockchain platform for public,
permissioned, and consortium deployments. It provides account and asset
management, on-chain permissions, and smart contracts through the Iroha
Virtual Machine (IVM).

> Workspace status and recent changes are tracked in [`status.md`](./status.md).

## First-release Scope

Iroha 3 is the first public release described by this repository. Workspace
defaults, quickstarts, SDK guidance, and operator documentation target Iroha 3,
where signed payload availability is a consensus requirement.
Public and in-depth guidance is maintained in the sibling `iroha-docs`
repository; this repository retains only concise contributor notes and
code-adjacent specifications.

## Repository Layout

- [`crates/`](./crates): core Rust crates (`iroha`, `irohad`, `iroha_cli`, `iroha_core`, `ivm`, `norito`, etc.).
- [`integration_tests/`](./integration_tests): cross-component network/integration tests.
- [`IrohaSwift/`](./IrohaSwift): Swift SDK package.
- [`kotlin/`](./kotlin): Kotlin/JVM SDK for Kotlin and Java consumers, with separate Android client and wallet modules.
- [`javascript/iroha_js/`](./javascript/iroha_js), [`python/`](./python), and [`csharp/`](./csharp): JavaScript, Python, and .NET SDKs.
- [`docs/`](./docs): concise repository-local and code-adjacent documentation;
  public Iroha 3 documentation is maintained in
  [`iroha-docs`](https://github.com/hyperledger-iroha/iroha-docs).

Use the [dependency and ownership map](./docs/repository_map.md) to locate
implementation boundaries, SDK modules, and validation owners.

## Quickstart

### Prerequisites

- Rust 1.93.1, pinned by [`rust-toolchain.toml`](./rust-toolchain.toml)
- Optional: Docker + Docker Compose for local multi-peer runs

### Build and Test (Workspace)

```bash
cargo test
cargo build --workspace
cargo test --workspace --features iroha_torii/test-fixtures
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

Notes:

- Plain `cargo test` from the repository root runs the default workspace
  members. For an explicit full-workspace run including all Torii integration
  targets, use `cargo test --workspace --features iroha_torii/test-fixtures`.
  A full Torii run uses `cargo test -p iroha_torii --features test-fixtures`;
  owning unit-test mutation checks use `--lib` without that feature.
  Use `cargo test -p <crate>` for other focused crate suites.
- Ordinary builds use Cargo's native jobserver and libtest's normal thread
  selection. Memory-constrained evidence, packaging, and network lanes set
  explicit local limits in their own scripts instead of serializing every
  developer build. `cargo build --workspace` builds libraries and the shipping
  executables; generators, probes, benchmarks, and evidence programs require
  their explicit target feature, normally `--features dev-tools`.
- Full workspace build can take about 20 minutes.
- Full workspace tests can take multiple hours.
- On WSL, make sure the Windows-side `.wslconfig` gives the VM enough memory,
  swap, and host disk headroom for a large Rust workspace. Plain `cargo test`
  is now conservative by default; if the VM is still constrained, use
  `scripts/run_full_tests.sh --wsl-safe --target-dir /tmp/iroha-wsl-tests` to
  also serialize libtest execution.
- The workspace targets `std`; IVM is the sole Iroha VM. Wasm, WASI, and no-std implementations, SDK adapters, build targets, and release artifacts are prohibited.
- Heavier local UI/media helpers are explicit features in default builds:
  `cargo run -p mochi-ui --features gui` for the egui desktop shell and
  `cargo run -p iroha_cli --features offline-visual-codecs -- offline petal
  encode --format gif ...` for Petal Stream animated GIF output. The SoraFS browser/SDK local QUIC proxy is available
  with `cargo build -p sorafs_orchestrator --features local-quic-proxy`.

### AArch64 Linux cross builds

Use the corrected Zig driver for GNU/Linux release builds; it preserves static
crypto libraries and the assembly features already requested by their sources:

```sh
scripts/cargo_zigbuild_linux.sh --jobs 6 -- zigbuild --locked --profile release \
  --target aarch64-unknown-linux-gnu -p irohad --bin iroha3d_taira
```

Prerequisites are Python 3.10+, Cargo with `cargo-zigbuild`, Zig, and the Rust
Linux target. Set `IROHA_ZIG_BINARY` to an absolute Zig executable when pinning a
release toolchain. Reuse the same Cargo target directory. A release still needs
its clean signed source, recorded tool identities and runtime qualification.

### Fast Local Rust Loops

Keep Cargo's default target directory warm and scope the command to the crate
or binary being changed. The helper keeps the system linker by default,
enables `sccache` when installed, and exposes opt-in modes for repeated local
work:

```bash
# Fast source-check loop; Git commits do not invalidate status-only build metadata.
scripts/cargo_fast.sh --stable-local-metadata -- check -p iroha_core --lib

# Iterate on the node leaves together (irohad, iroha_cli, iroha_torii and
# iroha_kagami in one invocation) so they share one feature-unified iroha_core
# artifact per edit. Per-crate checks still catch crate-specific feature gates.
scripts/cargo_fast.sh --stable-local-metadata --incremental --node-set

# Repeated tests in a stable target lane; incremental test compilation uses more disk.
scripts/cargo_fast.sh --target-slot core-tests --incremental -- \
  test -p iroha_core --lib <test_name>

# Runnable optimized binaries without paying the production release-profile cost.
scripts/cargo_fast.sh --stable-local-metadata -- \
  build --profile local-release -p irohad --bin iroha3d
```

Omit `--jobs` to let Cargo use its native jobserver; use `--jobs N` only to cap
memory-heavy local builds. Use a small number of
stable `--target-slot` names only when concurrent tasks need isolated Cargo
locks; creating a fresh dated or temporary target for every build defeats
incremental reuse. For intentionally cold or isolated lanes, use
`--no-incremental` to improve `sccache` reuse across targets. Incremental mode
(`--incremental` or inherited `CARGO_INCREMENTAL=1`) explicitly disables
config-selected compiler wrappers so a configured `sccache` cannot reactivate.
To retain compiler instrumentation, set `RUSTC_WRAPPER` or
`CARGO_BUILD_RUSTC_WRAPPER` explicitly to its executable; `RUSTC_WRAPPER` takes
precedence, including an explicit empty value. The
wrapper clears the exact single-worker Cargo/CMake fingerprint inherited from
local automation so its fast defaults can take effect; pass
`--preserve-build-limits` when those inherited limits are intentional. Explicit
test-runner limits such as `RUST_TEST_THREADS` are preserved. The
`local-release` profile and `--stable-local-metadata` are local-development
tools only; release, packaging, and evidence workflows must keep using the
unchanged `release` or `deploy` profiles and exact source metadata. Linker
selection is explicit (`--linker auto` or `--linker <path>`) because a linker
that is faster on one platform can be slower on another.

### Targeted Test Commands

```bash
cargo test -p <crate>
cargo test -p <crate> <test_name> -- --nocapture
```

### SDK Test Commands

```bash
cd IrohaSwift
swift test
```

```bash
cd java/iroha_android
JAVA_HOME=$(/usr/libexec/java_home -v 21) \
ANDROID_HOME=~/Library/Android/sdk \
ANDROID_SDK_ROOT=~/Library/Android/sdk \
./gradlew test
```

## Run a Local Network

Start the provided Docker Compose network:

```bash
cargo run --bin kagami -- localnet \
  --seed Iroha --peers 4 --sora-profile nexus --consensus-mode npos \
  --out-dir target/compose-genesis
export IROHA_GENESIS_SIGNED_FILE="$PWD/target/compose-genesis/genesis.signed.nrt"
export IROHA_GENESIS_PUBLIC_KEY_FILE="$PWD/target/compose-genesis/genesis.public_key"
export IROHA_GENESIS_EXPECTED_HASH_FILE="$PWD/target/compose-genesis/genesis.expected_hash"
docker compose -f defaults/docker-compose.yml up
```

The checked-in `defaults/genesis.template.json` is a non-signable source and is
not consumed by this path. `kagami localnet` creates a complete disposable
manifest whose ordered validator BLS keys and proofs of possession define
generation zero; it retains the matching development-only keys in the
owner-controlled output directory. It contains no production signing key or
runtime signer and fails closed when any read-only trust-root input is missing.
For a normal generated network, use `kagami localnet` followed by `kagami docker`
without `--seed`; Kagami validates and reuses the authoritative validator
bundle, then embeds the three artifact paths directly. See the
[Kagami swarm guide](./crates/iroha_kagami/docs/swarm.md).

Use the CLI against the default client config:

```bash
cargo run --bin iroha -- --config ./defaults/client.toml --help
```

For daemon-specific native deployment steps, see [`crates/irohad/README.md`](./crates/irohad/README.md).

## API and Observability

Torii exposes both Norito and JSON APIs. Common operator endpoints:

- `GET /status`
- `GET /v1/pipeline/preflight`
- `GET /metrics`
- `GET /v1/parameters`
- `GET /v1/events/sse`

Node-local reads that expose peer addresses, clock state, pipeline load or
policy, and recovery/retention internals are not public projections. In the
first release, `GET /v1/peers`, `/v1/time/status`,
`/v1/pipeline/preflight`, `/v1/pipeline/recovery/{height}`, `/v1/policy`, and
`/v1/proofs/retention` require a fresh `OperatorSignature` bound to the exact
genesis `NetworkId`, method, substituted path, query, and empty body. Operator
clients dispatch each read once with redirects and retries disabled; bearer or
API-token fallback is not accepted. The peer diagnostic response is bounded by
the resolved P2P total-connection ceiling, and proof-retention status aggregates
counts in one pass without materializing proof identifiers.

For liveness checks, prefer the queue-aware fields in `/status`: use
`queue_size` as the gate and compare `time_since_last_block_ms` against your
alert threshold; `/v1/pipeline/preflight` reports the chain
`sumeragi.block_cadence_ms`. An old block
timestamp alone is not a stall when the queue is empty.

See the full endpoint reference in the
[public Iroha documentation](https://docs.iroha.tech/reference/torii-endpoints.html).

Contract deployment is a locally signed consensus transaction flow. Clients
upload and finalize bytecode, register the locally signed manifest, then submit
`CommitContractDeployment` with the exact expected authority nonce and previous
alias target. Torii never accepts deployment private keys and does not expose a
server-side deploy or deploy-bundle route. The maintained public HTTP paths are:

- `GET /v1/contracts/artifacts/{dataspace_id}/{code_hash}` and
  `GET /v1/contracts/artifacts/{dataspace_id}/{code_hash}/bytes` for registered artifacts
- `POST /v1/contracts/aliases/resolve` for the current signed alias binding
- `POST /v1/contracts/view/batch` for batched read-only contract queries in one
  round-trip

For the public-safe Torii posture, contract call/view/status routes stay public.
The bounded app surfaces ship enabled so a default node exposes its complete
production API:

- `torii.webhooks_enabled = true` by default, with destination guard rails
- `torii.zk_attachments_enabled = true` by default, with quotas and sanitization
- trader/app rollups such as `/v1/contracts/rollups/swaps/fills` and
  `/v1/contracts/rollups/trader/account` remain app-facing surfaces rather than
  part of the public-safe baseline
- deployments may explicitly disable either subsystem when policy requires a
  reduced surface

## Codex Integration

This repo includes Codex-facing SORA live-network surfaces:

- [`plugins/iroha/`](./plugins/iroha): an installable Codex app/plugin with the
  built-in Taira MCP preset.
- [`skills/sora-taira-testnet/`](./skills/sora-taira-testnet): a standalone
  Codex skill for live Taira testnet workflows.
- [`skills/sora-minamoto-mainnet/`](./skills/sora-minamoto-mainnet): a
  standalone Codex skill for live Minamoto mainnet workflows.

Install a standalone skill from a GitHub checkout of this repo with:

```bash
python3 "${CODEX_HOME:-$HOME/.codex}"/skills/.system/skill-installer/scripts/install-skill-from-github.py \
  --repo <owner>/<repo> \
  --path skills/sora-taira-testnet

python3 "${CODEX_HOME:-$HOME/.codex}"/skills/.system/skill-installer/scripts/install-skill-from-github.py \
  --repo <owner>/<repo> \
  --path skills/sora-minamoto-mainnet
```

Restart Codex after installation so the selected skill appears in the Skills
tab.

Start a disposable four-validator Taira network with
`python3 scripts/taira_devnet.py up --inrou-canary-dir <owner-only-workspace>`;
inspect it with `check` and stop it with `down`. `up` is a
Linux/AArch64/root/KVM and mandatory guest-workload qualification run bound to
the current `optimizations` worktree and freshly built target-specific
binaries. Taira peer lifecycle state is recorded only in owner-only
`peerN.process.json` V1 identities and is controlled through held Linux pidfds;
legacy PID files and non-Linux process-control fallbacks are rejected. `check`
is read-only and requires the exact owner-only V1 guest
qualification record produced by `up`; it revalidates the retained input,
stage, CLI/source/target identities, and fresh four-route live evidence without
repeating the mutating canary or signed ping.
The command
delegates config/genesis generation to the current Kagami binary and
transaction/API checks to the current daemon and CLI. See
[`configs/soranexus/taira/README.md`](./configs/soranexus/taira/README.md).

## Core Crates

- [`crates/iroha`](./crates/iroha): client library.
- [`crates/irohad`](./crates/irohad): peer daemon binaries.
- [`crates/iroha_cli`](./crates/iroha_cli): reference CLI.
- [`crates/iroha_core`](./crates/iroha_core): ledger/core execution engine.
- [`crates/iroha_config`](./crates/iroha_config): typed configuration model.
- [`crates/iroha_data_model`](./crates/iroha_data_model): canonical data model.
- [`crates/iroha_crypto`](./crates/iroha_crypto): cryptographic primitives.
- [`crates/norito`](./crates/norito): deterministic serialization codec.
- [`crates/ivm`](./crates/ivm): Iroha Virtual Machine.
- [`crates/iroha_kagami`](./crates/iroha_kagami): key/genesis/config tooling.

## Documentation

Public and in-depth Iroha 3 documentation is published at
[docs.iroha.tech](https://docs.iroha.tech/) from the
[`hyperledger-iroha/iroha-docs`](https://github.com/hyperledger-iroha/iroha-docs)
repository.

This repository keeps concise contributor guidance and documentation coupled to
the implementation, including the [`docs/` index](./docs/README.md), the
[Norito wire-format specification](./norito.md), crate and SDK READMEs, formal
artifacts, and the current [`status.md`](./status.md) and
[`roadmap.md`](./roadmap.md). Building or testing Iroha does not require a
sibling `iroha-docs` checkout.

Consensus is the sans-IO Sumeragi core in
[`crates/iroha_sumeragi`](./crates/iroha_sumeragi), specified with its safety
and liveness argument in [`specs/sumeragi.md`](./specs/sumeragi.md). Its
deterministic simulator tests run with `cargo test -p iroha_sumeragi`, and
`scripts/sumeragi_mutation_gate.py` checks that every protocol mutation listed
in the spec is killed by a named test.

## Translations

Localized public documentation is published at
[docs.iroha.tech](https://docs.iroha.tech/) and maintained in
[`iroha-docs`](https://github.com/hyperledger-iroha/iroha-docs).

## Contributing and Help

- Contribution guide: [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- Community/support information: [public Iroha documentation](https://docs.iroha.tech/)
- Security policy: [`SECURITY.md`](./SECURITY.md)

## License

Iroha is licensed under Apache-2.0. See [`LICENSE`](./LICENSE).

Documentation is licensed under CC-BY-4.0: http://creativecommons.org/licenses/by/4.0/
