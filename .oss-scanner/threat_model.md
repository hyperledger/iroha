# Threat model: Hyperledger Iroha 3

This file guides Anthropic's OSS Scanner through this repository. The scanned branch is `optimizations`, the active
development line. Iroha 3 is in its first release and keeps no backward compatibility, so retired layouts, aliases and
fallback decoders are rejected on purpose. Public SORA networks (the Taira testnet and the Minamoto mainnet) run
Iroha 3. Never contact them; work only against the local network described below.

## What this project does and where untrusted input enters

`iroha3d` is a blockchain node. It consists of:

- Torii, the HTTP, WebSocket and SSE API
- P2P networking
- Sumeragi BFT consensus
- transaction execution: built-in instructions plus IVM bytecode compiled from Kotodama (`.ko` to `.to`)
- Kura block storage

Norito is the binary and JSON codec for everything on the wire and on disk; its layout is in `norito.md`. Accounts
follow a universal model: `AccountId` is a domainless key-based identity, and aliases are a separate binding layer.
Lanes are separate Sumeragi core instances whose certified blocks the global chain merges (`specs/sumeragi_lanes.md`).
An independently signed data space root owns its State and local finality (`specs/sumeragi.md` §11).

Treat the following as attacker-controlled, roughly from the weakest attacker to the strongest:

- **Any internet client.** Any client can send Torii requests:
  - Norito-RPC: `POST /v1/pipeline/transactions`, `POST /v1/query`
  - the JSON app API, WebSocket and SSE streams
  - the MCP JSON-RPC endpoint (`crates/iroha_torii/src/mcp.rs`)
  - the Connect relay (`connect.rs`)
  - attachment and content uploads
  - the SoraFS and Soracloud gateways (`sorafs/api.rs`, `soracloud.rs`)
  - Kotodama source compilation (`contract_sources.rs`)
  - contract view and simulate routes, which run IVM outside consensus
- **Any account holder.** An account holder signs transactions with arbitrary instructions, metadata, IVM bytecode to
  deploy or invoke, triggers, ZK proofs and attachments. Accounts are cheap to create on a local network.
- **Any network peer before authentication.** It controls TLS 1.3 over TCP handshakes, handshake frames of up to
  `u16::MAX` bytes and proof-of-work admission. After authentication it can send every `NetworkMessage`
  (`crates/iroha_core/src/lib.rs`): transaction and peer gossip, time samples, Torii proxy traffic, streaming
  control and Sumeragi frames.
- **Up to f Byzantine validators of a 3f + 1 committee** (f = ⌊(n − 1)/3⌋, quorum q = n − f). They can:
  - equivocate, propose invalid blocks, withhold proposals or payloads, or skew their clocks
  - forge sync responses and block bodies
  - send malformed votes, certificates, `PayloadManifest`s and `PayloadChunk`s
  
  Safety must hold against all of this, and liveness must recover as `specs/sumeragi.md` describes. Observers and
  candidate pools never vote.

These are trusted:

- the node operator, their configuration files and keys, including the operator keys allowlisted for operator routes
- genesis, which is the chain's trust root, and chain parameters from committed state
- the node's own storage directories

Bugs in how the node verifies signatures, freshness or replay of operator requests are in scope; a compromised
operator key is not. Data the node reads back from its own disk (Kura, snapshots, safety records) matters less than
network input, but the decoders still enforce canonical form.

## Components that matter most / least

In priority order:

1. **Consensus safety and finality.**
   - `crates/iroha_sumeragi/src/`: the sans-IO core.
     - `message.rs`: `WireMessage::decode` with a frame limit.
     - `crypto.rs`: `verify_qc`, `verify_tc`, `verify_vote`, proposal signatures.
     - `availability.rs`: payload manifests and rows.
     - `safety.rs` and `machine/`.
   - `crates/iroha_core/src/sumeragi/`: the node driver.
     - Per-peer ingress limits in `net.rs`.
     - `driver/payload_worker.rs`.
     - Lane merge and routing in `lanes/`.
     - BLS proof-of-possession checks in `crypto.rs`.
   - Every PrepareQC, CommitQC and TimeoutCert carries exactly q votes from distinct committee members; signer
     supersets are invalid. The contract is `specs/sumeragi.md`.
2. **Transaction admission, execution and authorization.**
   - `crates/iroha_core/src/tx.rs`: `AcceptedTransaction::accept`.
     - It checks chain binding, clock drift, TTL and expiry, signing-algorithm policy, signatures, size, attachment
       and instruction limits.
     - Batched Ed25519 verification must accept exactly what single verification accepts.
   - `queue.rs`: replay and per-account limits.
   - `executor.rs`: permission validation, fee admission and contract code hashes.
   - `smartcontracts/isi/**`: every instruction, including parameter changes in `world.rs` and triggers.
   - `state.rs`: trigger execution and depth limits.
   - `block.rs`: block validation.
3. **IVM.**
   - `crates/ivm/src/`:
     - `ivm.rs`: program loading and the interpreter. There is no JIT.
     - `memory.rs`: region permissions and alignment.
     - gas metering.
   - `crates/ivm_abi/src/`: `syscalls.rs` (`is_syscall_allowed`) and `pointer_abi.rs` (TLV validation).
   - The host syscalls in `crates/iroha_core/src/smartcontracts/ivm/host.rs`.
   - Contract admission:
     - `crates/ivm_artifact_admission/`.
     - Deployment in `smartcontracts/isi/world.rs` and `smartcontracts/code.rs`, which enforce `code_hash` and
       `abi_hash`.
   - Unknown syscall numbers must trap with `VMError::UnknownSyscall`. ABI rules: `crates/ivm/docs/`.
4. **Norito decoding of untrusted bytes.**
   - Entry points:
     - `crates/norito/src/core.rs`: `from_bytes`, `decode_from_bytes_with_limits`, `DecodeLimits`,
       `Header::read`.
     - `lib.rs`: canonical decoding for admission.
     - `framed_decode.rs`.
     - `columnar.rs`, `aos.rs`, `json/` and `streaming/`.
   - Unsafe code: the thread-local payload pointer in `core.rs`, `core/simd_crc64.rs` and `core/gpu_zstd.rs`.
   - Norito has the most `unsafe` of any node-path crate.
5. **Torii.**
   - Every route declares its authentication mode: `crates/iroha_torii/src/router/builder.rs` and
     `crates/iroha_torii_shared/src/route_catalog.rs`.
   - Operator and app signatures: `operator_signatures.rs`, `app_auth.rs`, `bounded_replay_cache.rs`.
     - `enforce_identity_bound_signature` leaves key binding to the handler.
   - Pre-auth gates and rate limits: `limits.rs` and `enforce_preauth` in `lib.rs`.
   - Webhook destinations and SSRF checks: `webhook.rs`.
   - Attachments and the sandboxed sanitizer: `zk_attachments.rs`, `zk_attachments/sanitizer.rs`,
     `bin/attachment_sanitizer.rs`.
   - The query filter DSL: `crates/iroha_torii_shared/src/list_query/`.
   - `iroha-threat-model.md` at the repository root analyses Torii in depth.
6. **P2P.**
   - `crates/iroha_p2p/src/`:
     - `transport.rs`: TLS 1.3 with ALPN `iroha-p2p/1`.
     - `network.rs`.
     - `peer.rs`: the handshake, frame caps and decode limits.
     - `preauth.rs` and `puzzle_work_admission.rs`: per-source admission.
   - Shipping QUIC constructors currently reject before creating an endpoint, pending transport requalification.
     The feature-gated QUIC implementation is available for review but is not a reachable shipping transport.
   - Handshake cryptography: `crates/iroha_crypto/src/soranet/`.
   - ML-KEM and ML-DSA run as C code through `crates/soranet_pq/`.
7. **Cryptography and proof verification.**
   - `crates/iroha_crypto/src/signature/`: Ed25519 strict and batch, secp256k1, BLS through `blst`, ML-DSA, SM2,
     GOST.
   - `public_key_decode.rs`.
   - On-chain verifiers:
     - `crates/iroha_core_zk/src/verification.rs`
     - `crates/iroha_core_privacy/`
     - `crates/iroha_zkp_halo2/`
     - `crates/iroha_plonk/src/verifier.rs`
     - proof verification in `crates/fastpq_prover/`
     - `crates/kaigi_zk/`
     - the KAGEMUSHA offline-payment proofs in `crates/iroha_kagemusha_proof/` and
       `crates/iroha_core/src/smartcontracts/isi/kagemusha_wallet.rs`
   - A verifier that accepts a false statement is a soundness break.
8. **Determinism across hardware.** Validators on different hardware must compute identical results for the same
   block.
   - SIMD paths must equal the scalar path:
     - `crates/ivm/src/vector.rs` (SSE2, AVX2, AVX-512, NEON chosen at runtime)
     - `bn254_vec.rs`, the AES and SHA-256 kernels
     - Norito CRC64
     - the RS16 erasure kernel in `crates/iroha_primitives/src/erasure/rs16/kernel.rs`
   - The same rule applies to the CUDA and Metal paths. They are in scope for review but cannot run here.
9. **Persistence and startup.**
   - `SignedBlockWire` canonical decoding: `crates/iroha_data_model/src/block/mod.rs`.
   - `crates/iroha_core/src/kura.rs` and `snapshot.rs`.
   - Node startup: `crates/irohad/src/`.

Also in scope:

- `iroha3d_taira` and its Soracloud runtime (`crates/irohad/src/soracloud_runtime*.rs`). It runs hosted handlers and
  VMs behind Torii's public gateway. Its QEMU, bwrap and pidfd setup cannot run in this image.
- The locally patched crates under `vendor/`, because the node ships them.
- A flaw in a third-party crate, when Iroha makes it reachable. Show the path from Iroha's API and name the crate the
  fix belongs in.

Lower priority:

- Client tooling: the `iroha` CLI, `kagami`, `koto` and the `crates/iroha` client library. Code that the node also runs
  on network input keeps node priority; for example, Torii compiles Kotodama source.
- The mobile FFI bridge `crates/connect_norito_bridge/`.

Out of scope:

- SDKs and apps: `IrohaSwift/`, `kotlin/`, `java/`, `javascript/`, `python/`, `csharp/`, `examples/` and the
  `mochi*` GUI crates.
- Test-only code:
  - `integration_tests/`, `crates/iroha_test_network/`, `crates/iroha_test_samples/`, the `izanami` chaos tool
  - `tests/` and `benches/` directories, `#[cfg(test)]` code
  - features named `sim`, `mutation-testing`, `fault_injection`, `test-fixtures`, `*-tests` and `test-network-*`
- Tooling, deployment examples and docs: `xtask`, `scripts/`, `ci/`, `.github/`, `release/`, `deploy/`, `defaults/`,
  `docs/`, and the corpora under `fuzz/`.

## How to exercise it

**The image.**
- `/src` is a checkout of `optimizations`, `.git` included, built with the toolchain from `rust-toolchain.toml`
  (rustfmt and clippy installed).
- `CARGO_NET_OFFLINE=true` prevents registry access. `CARGO_INCREMENTAL=0` and the mold linker setting in
  `/usr/local/cargo/config.toml` match the prebuilt artifacts; changing compilation settings such as these,
  `RUSTFLAGS` or a profile can invalidate those artifacts.
- `/opt/oss-scanner/build.log` records completion of every prebuild. The shared compilation budget defaults to 28
  minutes, leaving time for image export and unpacking. It starts after dependency fetch and is reset whenever the
  compilation layer runs, including after cached setup layers. Package and toolchain installation, dependency
  fetch, image export and unpacking are outside that budget and still count toward the scanner's overall build
  limit. An unfinished prebuild, compile error, abnormal exit (including SIGKILL), missing binary or failed CLI
  startup probe fails the image build. Cargo timing reports are in `target/cargo-timings/`; the build log also
  prints the target directory size after each compilation group.

**Prebuilt, in this order:**
1. The release binaries in `target/debug/`: `iroha3d`, `iroha3d_taira`, `sorafs_governance_dag`,
   `sorafs_external_software_signer`, `iroha` (the CLI), `attachment_sanitizer`, `koto` (the Kotodama compiler)
   and `kagami`. They share a Cargo invocation; Kagami adds the data model's exact-12 conformance helper exports
   to this graph. Simulator and test-fixture features are not enabled in these binaries.
2. All default test harnesses and example build checks from
   `cargo test --no-run -p norito -p iroha_crypto -p ivm -p iroha_p2p`, sharing those packages' dependency features.
3. All default test harnesses and example build checks from `cargo test --no-run -p iroha_sumeragi --features sim`,
   in a separate graph so simulator features do not enter the other prebuilds.

The binaries use the dev profile and the tests use the test profile. Both enable debug assertions and overflow
checks.

**Building on this machine (2 CPUs, 8 GB).**
- Rebuilding `iroha_core` (about 1.5M lines) or anything above it takes hours here, so run the prebuilt binaries
  directly.
- Cargo resolves features per invocation. Retain all four package selections when running a filtered codec,
  crypto, IVM or P2P test to reuse that prebuild. A standalone `-p` or another `--features` combination may require
  additional compilation. The shared test graph includes dependency features such as FHE test fixtures and CUDA
  admission helpers; it does not enable hardware qualification targets or change the shipping binary graph.
- `crates/iroha_plonk/build.rs` makes Cargo rebuild it, and everything above it, on every invocation. The image
  works around this.
  - After you build a new configuration that includes `iroha_plonk` (anything that depends on `iroha_data_model` or
    `ivm`), run `pin-iroha-plonk` once.
  - The workaround suppresses discovery of newly added source files until another watched input changes or the
    sentinel is removed. It does not establish source-identity freshness after such changes.

**Reproducers as tests.**
- The main crates set `autotests = false` and group their integration tests.
- To add one:
  1. Write `crates/<crate>/tests/<name>.rs`.
  2. Add `#[path = "../<name>.rs"] mod <name>;` to one of the crate's `tests/grouped/group_NN.rs` files.
  3. Run `cargo test -p <crate> --test <crate>_group_NN <name>`. Test target names are in the crate's `Cargo.toml`.
- A grouped test avoids changing the crate's `src/`, but the native source-identity build script also watches test
  inputs. Editing them can still rebuild `iroha_plonk` and dependent crates.

```sh
cd /src
cargo test -p norito -p iroha_crypto -p ivm -p iroha_p2p # all four prebuilt suites
cargo test -p norito -p iroha_crypto -p ivm -p iroha_p2p <test> # filter without changing dependency features
cargo test -p iroha_sumeragi --features sim            # consensus core and deterministic simulator
SUMERAGI_SIM_SEED=<n> SUMERAGI_SIM_TRACE=1 cargo test -p iroha_sumeragi --features sim <test>  # replay one seed
```

**A local network.** It needs four validators, the minimum committee size; a single-peer network is rejected by
design.

```sh
/src/target/debug/kagami localnet generate --out-dir /tmp/net --peers 4 --seed audit \
  --bind-host 127.0.0.1 --public-host 127.0.0.1
cd /tmp/net && IROHAD_BIN=/src/target/debug/iroha3d IROHA_CLI=/src/target/debug/iroha bash ./start.sh
curl -s http://127.0.0.1:8080/health                  # Torii on 8080-8083, P2P on 1337-1340
/src/target/debug/iroha -c /tmp/net/client.toml --fee-payer authority tx ping --msg hello
/src/target/debug/iroha -c /tmp/net/client.toml ledger domain list
bash ./stop.sh
```

- The first start can take a while.
- Use the generated `client.toml`. `defaults/client.toml` names a different network.
- Submitting transactions needs `--fee-payer`.
- Environment variables such as `CHAIN`, `PUBLIC_KEY`, `PRIVATE_KEY`, `TRUSTED_PEERS`, `P2P_ADDRESS`, `API_ADDRESS` and
  `KURA_STORE_DIR` override peer configuration, so keep them unset.
- `iroha --help` and `kagami localnet --help` list the other commands. `kagami localnet up`, `status`, `logs` and `down`
  manage a network for you.
- Do not use `scripts/run_local_swarm.sh`; it is out of date.

**Other ways in.**
- The integration-test harness can drive the prebuilt binaries:
  `IROHA_TEST_SKIP_BUILD=1 IROHA_TEST_REQUIRE_NETWORK=1 TEST_NETWORK_BIN_IROHAD=/src/target/debug/iroha3d
  TEST_NETWORK_BIN_IROHA=/src/target/debug/iroha cargo test -p integration_tests --test sumeragi`
- Compiling `integration_tests` is a new configuration of the whole node, though. Expect hours.
- Fuzz targets exist under `crates/norito/fuzz`, `crates/ivm/fuzz` and `crates/fastpq_prover/fuzz`. They need a nightly
  toolchain, `cargo-fuzz` and crates outside `Cargo.lock`, none of which this offline image has. Write targeted tests
  instead.

## How you rate severity

Production nodes run the `deploy` profile (release with LTO): no debug assertions and no overflow checks.

- An overflow panic in this dev build is silent wrapping in production. Rate what the wrapped value does, for example
  to a balance, a fee or a quorum count.
- A `debug_assert!` failure does not exist in production on its own.
- A panic that the deploy build also hits counts as a crash: explicit panics, `unwrap`, out-of-bounds indexing,
  allocation failure, stack overflow.

**Critical**

- Breaking consensus safety, whether by up to f Byzantine validators or by anyone outside the committee:
  - conflicting blocks finalized
  - finality reverted
  - a certificate accepted without exactly q valid votes from distinct committee members
  - the committee or chain parameters changed outside committed transactions
- An unauthorized state change:
  - acting for an account without its keys, by bypassing signatures, multisig, permissions or executor validation
  - minting, burning or moving assets without authority
  - a forged proof accepted by a verifier
- Remote code execution on a node.
- Escaping IVM isolation: reaching memory or state that the program's syscalls do not grant.
- A network-wide halt or a chain split from unprivileged input, meaning either of:
  - a transaction, block or message that crashes or stalls every honest validator
  - execution whose result differs between validators (hardware-dependent or nondeterministic)
- Disclosure of validator, operator or account private keys.

**High**

- Crashing, hanging or exhausting the memory of one node with an unauthenticated Torii request or pre-handshake P2P
  input.
- A lasting liveness loss caused by up to f Byzantine validators.
- A memory-safety bug (out-of-bounds access, use-after-free, uninitialized read, data race) in `unsafe` code that
  untrusted input reaches, even without a demonstrated exploit.
- Bypassing operator or app request signatures, their freshness or their replay protection.
- Server-side request forgery without operator authority: making the node connect to loopback, private or link-local
  addresses, through webhooks or any other outbound request.
- Escaping the attachment sanitizer's sandbox.
- A gas, fee or size-limit bypass that lets one transaction consume unbounded validator CPU, memory or storage.
- Disclosure of confidential transaction data to parties the protocol excludes.

**Medium**

- Denial of service that needs any of these, or that existing rate limits bound:
  - sustained traffic
  - a funded account
  - a peer or validator identity
- A crash that needs an authenticated peer or a validly signed operator request, without key compromise.
- Disclosure of operational data that is not meant to be public.

**Low**

- Anything that needs write access to the node's configuration, keys, storage or genesis.
- Misconfiguration against documented defaults.
- Crashes of the CLI, `kagami` or `koto` on malformed local files.

**What a report should contain**

- the commit
- the features and configuration used
- the attacker's capability: client, account, peer, validator or operator
- a minimal offline reproducer: a grouped test, a simulator scenario with its seed, or a script against the local
  network
- expected and actual behaviour
- a patch with a regression test

Group reports that share a root cause.

Patches must follow `AGENTS.md`:

- no compatibility shims or fallback decoders
- Norito instead of serde
- quorums computed as `n - f`
- faults injected only in the simulator
- a mutation test killed by a named simulator test for every new safety or liveness rule

## Anything to leave alone

These are intended:

- Idle chains produce no blocks.
- Consensus faults exist only in the deterministic simulator and test-only features.
- A committee has 3f + 1 validators, 4 to 31, so smaller networks are rejected.
- Observers and candidate pools never vote; a lane validator signs only for its lane.
- Losing quorum halts an instance, with no local override.
- Operator routes such as `/v1/configuration` are reachable from the internet but require operator signatures.
- The node's own key is allowlisted for operator routes by default.
- `torii.require_api_token` defaults to false.
- `/health`, `/status` and `/metrics` are public.
- Keys are published test keys in all of these: `defaults/`, `crates/iroha_test_samples/`, generated localnets and test
  fixtures.
- Software key custody without an HSM is a deliberate choice.
- Genesis is trusted.
- Retired formats are rejected; this is the first release.

Also leave alone:

- The risks `iroha-threat-model.md` already documents, including conditional rate limits and attachment disk use.
  Report one only with a concrete exploit path beyond what that file describes.
- Hardening suggestions with no attack path.
- Findings that hold only in test-only code.
