# ivm
Iroha Virtual Machine (IVM)

ivm/                         # → Cargo workspace root (a single Rust library crate)
├── Cargo.toml               # crate manifest (name = "ivm", edition = 2024, deps: sha2, halo2curves, etc.)
├── README.md                # architecture overview, build & usage instructions
├── benches/                 # Criterion performance benchmarks
│   └── bench_vm.rs
├── examples/                # small runnable demos
│   ├── add.rs               # “hello‑world” ADD / HALT program
│   └── sha256.rs            # demo using the SHA256BLOCK instruction
│
│   Tuple return demo
│   - Example: `koto_tuple_return_demo.rs` compiles an inline Kotodama function
│     that returns a tuple and reads its completed result-table words.
│   - Run: `cargo run -p ivm --example koto_tuple_return_demo`
│   - Related source sample: `crates/kotodama_lang/src/samples/tuple_return_demo.ko` shows
│     tuple creation and destructuring with `.0`/`.1`.
├── src/
│   ├── lib.rs               # public re‑exports and crate‑level docs
│   ├── memory.rs            # region‑based memory manager (perm checks, loads/stores)
│   ├── registers.rs         # GPR & vector‑register structs + helpers
│   ├── gas.rs               # gas table and accounting utilities
│   ├── error.rs             # `VMError`, `Perm` and other enums
│   ├── instruction.rs       # opcode constants, field extractors, immed‑helpers
│   ├── decoder.rs           # fixed-width 32-bit instruction decoder
│   ├── host.rs              # `IVMHost` trait + default/dummy host impls
│   ├── syscalls.rs          # Iroha‑specific syscall number map & helpers
│   ├── vector.rs            # SIMD helpers, SHA‑256 compression adapter
│   ├── zk.rs                # zero‑knowledge‑mode helpers (ASSERT tracking, padding)
│   └── ivm.rs               # `IVM` struct, fetch-decode-execute loop, public API
├── tests/                   # `cargo test` integration + property tests
│   ├── arithmetic.rs        # ADD/SUB/MUL/… correctness
│   ├── memory.rs            # loads/stores, OOB & alignment traps
│   ├── control_flow.rs      # branches, jumps, JAL/JR, HALT behaviour
│   ├── syscalls.rs          # host interaction and error propagation
│   └── zk_mode.rs           # ASSERT, padding to MAXCYCLES, constraint‑failure paths
└── .github/
    └── workflows/ci.yml     # continuous‑integration script (fmt, clippy, tests)

# IVM – Iroha Virtual Machine

**IVM** is a Rust library implementing the Iroha VM for executing Iroha smart contract bytecode. It implements the IVM instruction set (not RISC‑V) with a canonical 32‑bit wide instruction format, gas metering, and cryptographic helpers. Only aligned 32-bit IVM instructions are executable.

Kotodama smart contracts compile to IVM bytecode (`.to`); they do not target “risc5”/RISC‑V as a standalone ISA. Observable behavior and outputs are defined by IVM across all hardware. For the current architecture and its proof-admission boundary, see [docs/architecture_spec.md](docs/architecture_spec.md).

## Status

- Implemented:
  - 256 general-purpose registers with privacy tags and Merkle commitments (current implementation; the encoding leaves headroom for future expansion).
  - Region-based memory with permissions and alignment checks; bulk copy helpers.
  - Gas metering; `GETGAS` and per-op cost accounting.
  - Syscall/host trait with a default host implementation.
  - Vector helpers with runtime SIMD detection (SSE/AVX/NEON) and scalar fallback; SHA-256 compression accelerated via Apple Metal when available.
  - AES, SHA-3, Poseidon helpers and BN254 utilities on CPU; Ed25519, ECDSA, and deterministic ML-DSA verification.
  - Declared state-access sets and transactional host checkpoints for host-side transaction scheduling.
  - OpenVerify IPA/Pasta proof-envelope verification in the host and bounded ZK trace logging (see `zk.rs` and `zk_verify.rs`).

### Gated test suites

- VRF tests (BLS/VRF helpers): gated by feature `ivm_vrf_tests`.
  - Run: `cargo test -p ivm --features ivm_vrf_tests vrf`
- ZK/backend-heavy tests (BN254, Poseidon parity, proof envelopes, and Merkle proofs): gated by feature `ivm_zk_tests`.
  - Run: `cargo test -p ivm --features ivm_zk_tests`
  - This keeps quick local runs fast while allowing full coverage on CI or dev machines.

### Zero-knowledge backend

`ivm` links the proof verifier from `iroha_zkp_halo2` unconditionally. Runtime application-proof checks go through typed OpenVerify IPA/Pasta envelopes. That verifier does not establish correctness of an IVM execution trace. The crate does not expose host recomputation helpers as Halo2 circuits; application circuits, proving keys, and public-instance bindings belong to the proof backend. There is no production verifier feature toggle.

Notes
- Real proving is not performed on consensus paths; the host verifies proofs only. Any future proving flows should run off‑chain or outside consensus‑critical logic.
- All paths remain deterministic across hardware (no nondeterministic parallel reductions). When acceleration is enabled, results are required to match scalar fallbacks bit‑for‑bit.
- Acceleration milestones (see `roadmap.md`, sections **WP1–WP4**) include:
  1. **CUDA helper surface present; release qualification pending** — the public CUDA helper surface covers vectors, SHA‑256/Merkle, Keccak, Poseidon2/6, AES rounds/batches, BN254, Ed25519, and bitonic sort, and downstream callers such as `iroha_core` use the stable `ivm` root exports instead of private module paths. Ordinary CUDA builds now require checked-in real PTX and fail closed because the 10 reproducible artifacts, full kernel qualification, and signed provenance manifest are not yet complete; see [`cuda/README.md`](cuda/README.md).
  2. **Metal vector hot path (delivered)** — interpreter vector ops (`VADD32/64`, `VAND`, `VXOR`, `VOR`, `VROT32`) now route through the shared vector helpers so Metal/CUDA/CPU back-ends are selected at runtime with deterministic fallbacks and chunked logical vector lengths (`roadmap.md`, WP2-A/B/D).
  3. **Ed25519 batch opcode (delivered)** — `ED25519BATCHVERIFY` consumes a bounded Norito request containing only the ordered entries, charges bytes before hashing/decoding and all admitted entries before cryptographic work, writes the first failure index to `rs2`, and verifies each entry exactly once with strict hardware-independent semantics (closing `roadmap.md`, WP3-A/B/C).
  4. **CRC64 GPU back-ends (delivered)** — Chunked Metal/CUDA helpers now feed `hardware_crc64` with a 192 KiB default cutoff (`NORITO_GPU_CRC64_MIN_BYTES` override) and support explicit helper overrides via `NORITO_CRC64_GPU_LIB` (stubbed in tests). The CUDA path composes per-chunk CRC outputs on-host, Metal mirrors the same chunking, and Stage‑1 cutovers were re-benchmarked (`examples/stage1_cutover` → `benchmarks/norito_stage1/cutover.csv`), keeping the scalar cutover at 4 KiB while aligning the Stage‑1 GPU minimum to 192 KiB, closing WP4-A/B/C.
  5. **Kotodama codegen completion (delivered)** — the Kotodama compiler now lives in `crates/kotodama_lang`, emits pointer-ABI-aware IVM bytecode, and generates first-release manifest metadata for permissions, state, triggers, and compiler-derived access hints. Dynamic or malformed helper payloads remain conservative instead of emitting guessed access descriptors.

## Kotodama

High-level smart contract language targeting IVM bytecode:

- Grammar and syntax (implemented surface): `docs/kotodama_grammar.md`
- Gaps vs. implementation and roadmap: see `docs/kotodama_gap_analysis.md` and `../../roadmap.md`


## Features

- **Register-based ISA:** 256 general-purpose **64-bit** registers (`r0`–`r255`) with `r0` fixed at zero. In zero-knowledge mode each register carries a 1-bit privacy tag. The ISA supports arithmetic (ADD, SUB, MUL, DIV, etc.), logic (AND, OR, XOR), memory loads/stores, control flow (jumps and branches), and system calls.
- **One Canonical Encoding:** Every executable instruction is one aligned 32-bit word. Program loading rejects compact and mixed-width streams before execution.
- **Memory Management:** Region-based memory with permission checks. Code, heap, input, output and stack regions are predefined. Misaligned or out-of-bounds accesses cause traps.
- **Indexed Literals:** `LDLIT` loads a validated pointer TLV and `LDI64` loads an exact signed scalar by a 16-bit table index, each in one word. Authenticated descriptor kinds, complete payload validation, and instruction-kind checks prevent aliases, malformed objects, and pointer/scalar confusion before execution.
- **Relaxed Direct Transfers:** The compiler uses one-word `JAL` for nearby calls/jumps and automatically relaxes farther targets to signed 24-bit `JMP`/`JALS` forms. `JALS` uses `r1` as the implicit link register.
- **Gas Accounting:** Each instruction consumes a specified amount of gas from a gas budget. Execution halts with an error if gas is exhausted before completion.
- **GETGAS Instruction:** Programs may query the current remaining gas via opcode `0x61` which writes the value to a destination register.
- **Extended Arithmetic:** Support for `DIVU`, `REMU`, `MULH` and `MULHU` instructions providing unsigned division, unsigned remainder and high-word multiplication.
- **Host Interoperability (Syscalls):** A trait-based host interface (`IVMHost`) allows the VM to invoke host environment services via the `SCALL` instruction (opcode `0x60`) with an 8-bit call number or the `SYSTEM`/SCALLX encoding with a 24-bit number. `DefaultHost` provides bounded local/test services only; production ledger authority is supplied by Iroha Core's execution host.
- **Kotodama ABI V1 calls:** Every compiled function uses caller-owned argument and result tables, with addresses and counts in `r10`–`r13`. Each table is bounded to 8,192 words (64 KiB), and the runtime validates its ownership, initialization and lifetime. See the [calling convention](docs/calling_convention.md).
 - **Vector Extensions:** CPU intrinsics (x86 SSE/AVX and AArch64 NEON) ship in every build and are selected at runtime after deterministic self-tests. The scalar implementation remains the fail-closed fallback. `SHA256BLOCK` may use a Metal kernel on macOS when the `metal` feature is enabled.
 - **Apple Metal (feature: `metal`, macOS-only):** When enabled and a compatible device is present, Metal kernels accelerate vector ops (`vadd*`, `vand`, `vxor`, `vor`) and SHA‑256 compression. The code is not compiled on non-macOS targets and falls back to CPU/SIMD when Metal is unavailable or disabled.
 - **CUDA (feature: `cuda`):** Linux/Windows daemon dependencies select the existing CUDA feature automatically. One source-owned optional authenticated bundle retains exact bytes through admission and launch. Current absent approval permits CPU-capable ordinary builds in every profile; supplied unreviewed, incomplete or malformed material fails integrity. No ordinary build or startup invokes a CUDA compiler.
- **ZK mode and execution proofs:** ZK mode tracks privacy tags, private memory and bounded diagnostic execution traces. Trace digests and Merkle logs do not prove execution correctness. Core rejects every `IvmProved` invocation and raw private-input access. Production private invocation requires the complete native STARK execution relation and authenticated finalized State foundation tracked in the [completion goals](../../specs/kotodama_ivm_completion.md).
- **Program Hashing:** When a program is loaded the VM computes a SHA-256 hash of the code. It can be obtained via `IVM::code_hash()` and supplied as a public input so verifiers agree on the exact contract that was executed.
- **Turing Complete & Gas-Limited:** Branching, jumping and memory operations allow any algorithm to be expressed. A contract must also supply a gas budget, ensuring execution halts deterministically.
- **Optimised for Financial Operations:** Fast 64-bit arithmetic and register access keep asset calculations efficient, suitable for high-throughput ledgers.
- **Bulk Memory Helpers:** `load_bytes` and `store_bytes` efficiently copy contiguous regions, speeding up cryptographic hashing and serialization.
- **Quantum-Resistant Signatures:** Deterministic ML‑DSA (Crystals Dilithium) verification ships in every IVM build. The shared `soranet_pq` verifier uses portable CLEAN verification when AArch64 NEON or SHA3 capability is unavailable; supported hardware retains acceleration with identical verification results. ISO 20022 ML-DSA signing uses the same guard while preserving its existing key decoding, empty FIPS context, and OS randomness behavior.
- **SIMD Poseidon Hashing:** `POSEIDON2` hashes two scalar registers and `POSEIDON6` hashes one six-register window, avoiding transient memory traffic. Both automatically use deterministic hardware acceleration when supported by the host CPU.
- **SIMD Field Arithmetic:** BN254 helpers are implemented on CPU with runtime SIMD detection plumbed through vector utilities. Wide reduction preserves four little-endian `u64` limbs on both 32-bit and 64-bit targets by decoding the reduced integer's fixed byte encoding. For benchmarking or deterministic testing, thread `AccelerationPolicy::with_forced_simd(Some(SimdChoice::{Scalar|Sse2|Avx2|Avx512|Neon}))` through `IvmConfig`, or call `ivm::set_forced_simd` in tests; unsupported requests automatically fall back to the scalar implementation to preserve safety. Future work: add architecture-specific intrinsics where beneficial.
- **Apple Metal Acceleration:** The process-owned queue and pipelines are shared through allocation-lifetime leases. Per-pipeline completed-dispatch receipts exclude startup probes and diagnostic kernels; the required `metal-hardware-tests` gate checks real execution and CPU parity. See [GPU qualification](docs/gpu_offloading.md#required-metal-execution-evidence). On macOS the VM accelerates vector lanes (`vadd32`/`vadd64`/`vand`/`vxor`/`vor`), SHA‑256 compression and tree reductions, Keccak‑f1600, AES rounds/batches, and non-opcode Ed25519 batch helpers via Metal when a compatible device is present. Production selection comes from the node's `[accel]` configuration; local embeddings may use `AccelerationPolicy::with_metal(true)`. Developer-only environment shims are ignored by release builds. CPU/SIMD fallbacks retain identical semantics. The consensus-visible `ED25519BATCHVERIFY` opcode always uses ordered strict CPU verification.
- **Optional backends remain deterministic:** Metal/CUDA are best-effort accelerators; when features are disabled or hardware is unavailable, helpers fall back to scalar/SIMD paths so results stay identical across hosts.
- **CUDA Acceleration:** The `cuda` feature covers vectors, SHA-256/Merkle, Keccak-f1600, Poseidon2/6, AES rounds/batches, BN254 arithmetic, non-opcode Ed25519 batch verification and scheduler bitonic sort. The private source `REVIEWED_CUDA_BUNDLE_PINS` pins the raw signer key and canonical signed manifest; its current value is `None`. Absence refuses before CUDA discovery and staging, and ordinary callers retain complete CPU fallback. Runtime limits remain file-configured through `[accel].enable_cuda`, `[accel].max_gpus` and finite resource limits. Genuine signed PTX, independent review and native qualification remain open in [`cuda/README.md`](cuda/README.md).
- **Host-owned Transaction Scheduling:** Hosts schedule transactions and publish their declared writes; each IVM executes one contract invocation sequentially.
- **Startup Jingle:** When built with the optional `beep` feature,
  `irohad` calls `IVM::beep_music()` and plays a short tune when the
  configuration enables it. Disable via `ivm.banner.beep = false` in your node
  config.
- **Merkle‑Backed Memory:** Memory writes are batched until `commit()` recomputes a Merkle root over the entire image. The root calculation now hashes chunks in parallel with Rayon for faster commits. Authentication paths can be requested for proofs.
- **Governed Heap Growth:** Hosts set a per-runtime heap ceiling. `SYSCALL_GROW_HEAP` may extend the active heap only up to that ceiling and never beyond the ABI address window.
- **Declared Access Sets:** Hosts receive each transaction's declared state accesses and report observed accesses, so host schedulers derive conflicts from declarations rather than execution history.
- **Full-width cryptography:** Register opcodes are limited to operations with coherent register-sized semantics. Full-width commitments, curve points, and pairing statements use typed syscall or proof-envelope boundaries instead of truncated register values.

## Memory Model

The VM divides memory into a set of regions. Code is loaded starting at
`0x0000_0000` and is marked read/execute only.  The heap begins at
`0x0010_0000`; its ABI-v1 address window ends at `0x0020_0000`. Hosts may set a
smaller deterministic per-runtime ceiling, and `SYSCALL_GROW_HEAP` cannot grow
past it. Allocations are requested through `SYSCALL_ALLOC`.
The read-only input buffer begins at `0x0020_0000` (64&nbsp;KB) and the
read/write output buffer begins at `0x0021_0000` (32&nbsp;KB). Finally the stack
begins at `0x0030_0000`; ABI V1 deterministically derives its active
64&nbsp;KiB–4&nbsp;MiB limit from the invocation gas budget. All loads and stores are checked
for permissions and proper
alignment by [`Memory`](src/memory.rs).  The entire memory image is committed
via a Merkle tree; pending writes are batched until `commit()` re-hashes only
the dirty subtrees, enabling succinct ZK proofs of state without touching
unchanged memory.

## Opcode Reference

IVM now standardises on the wide encoding (8-bit primary opcode + three 8-bit operand slots). The primary opcode ranges are:

- **0x01-0x26:** Integer arithmetic and logical operations (`ADD`, `SUB`, `MULH`, `DIVU`, `ADDI`, …).
- **0x30-0x35:** Memory and indexed-literal access (`LOAD64`, `STORE64`, `LOAD128`, `STORE128`, `LDLIT`, `LDI64`).
- **0x40-0x4B:** Control flow (`BEQ`, `BNE`, `JAL`, `JR`, `HALT`, `JMP`, `JALS`).
- **0x60-0x62:** System helpers (`SCALL`, `GETGAS`, `SYSTEM`).
- **0x70-0x78 / 0x80-0x8A:** Vector and cryptographic primitives (`VADD32`, `SETVL`, `PARBEGIN`, `SHA256BLOCK`, `POSEIDON6`, `AESENC`, `ED25519VERIFY`, …).
- **0x8B-0x9F:** Unassigned and rejected in ABI V1.
- **0xA0-0xA6:** Zero-knowledge field operations (`ASSERT`, `FADD`, `ASSERT_RANGE`).

See [`docs/opcodes.md`](docs/opcodes.md) for the full opcode tables, operand conventions, and encoding details. The canonical helpers in `encoding::wide` and `instruction::wide` cover the entire surface and are used throughout Kotodama and the runtime.

## Syscall Interface (ISI)

Smart contracts interact with the host ledger through `SCALL` (opcode `0x60`)
for 8-bit syscall ids and `SYSTEM`/`SCALLX` (opcode `0x62`) for 24-bit syscall
ids. The immediate operand selects an "Iroha Special Instruction" (ISI) whose
numeric assignments are listed in
[`syscalls.rs`](src/syscalls.rs).  The host implementation determines the exact
semantics and gas costs of these calls. Before dispatch, each host provides a
side-effect-free upper gas quote; the VM reserves it before entering host code
and refunds any difference from the reported actual cost. An unaffordable
syscall therefore cannot partially apply host effects.

## Build and Usage

Ensure you have Rust (edition 2024 or later). To include IVM in your project, add to `Cargo.toml`:
```toml
ivm = { path = "path/to/ivm" }
```

Build the library and run the test-suite with Cargo:

```bash
cargo build --release
cargo test
```

To enable the optional startup jingle, build `iroha3d` with the `beep` feature:

```bash
cargo build -p irohad --bin iroha3d --features beep
```

Beep runs by default; set `ivm.banner.beep = false` in your configuration to disable
it for local runs.

Linux/Windows daemon dependencies automatically select IVM CUDA; local IVM builds
may select the existing `cuda` feature explicitly. Ordinary Cargo needs neither
`nvcc` nor a driver. The current absent source approval keeps CPU fallback in
every profile. With a genuine reviewed bundle, the sole canonical verifier
authenticates exact immutable source/PTX bytes before runtime discovery. File
configuration `[accel].enable_cuda` and `[accel].max_gpus` retains its current
semantics (`0` means no device cap). Shipping CUDA requires genuine source approval,
complete signed material and separate actual-device completion evidence; ordinary
CPU-capable builds provide none of that qualification.

You can also override CPU SIMD detection via configuration: set
`AccelerationPolicy::with_forced_simd(Some(SimdChoice::Scalar|Sse2|Avx2|Avx512|Neon))`
when building an `IvmConfig`, or call `ivm::set_forced_simd` in tests/benches.
The runtime validates that the requested backend is actually available; if not,
the scalar path is used to avoid undefined behaviour.

```bash
cargo build --features cuda
```

See [docs/gpu_deployment.md](docs/gpu_deployment.md) for operational
guidelines, including a rollout plan for clusters with eight A100 GPUs.

Several small examples are provided. They can be executed with `cargo run`:

```bash
cargo run --example add       # simple ADD/HALT demo
cargo run --example sha256    # SHA256BLOCK vector instruction
```

### Kotodama toolchain

`koto` (crate `kotodama_toolchain`) is the single V1 frontend for checking,
building, testing, formatting, documenting, explaining diagnostics, and
language-server integration:

```bash
# Parse, resolve, type-check, and analyze source
cargo run -p kotodama_toolchain --bin koto -- check path/to/contract.ko

# Emit machine-readable diagnostics
cargo run -p kotodama_toolchain --bin koto -- check --format json path/to/contract.ko

# Build a canonical deployable artifact and hash-keyed sidecars
cargo run -p kotodama_toolchain --bin koto -- build path/to/contract.ko

# Run contract tests
cargo run -p kotodama_toolchain --bin koto -- test path/to/contract.test.ko
```

## Benchmarking

Criterion-based benchmarks live under `benches/` and are run with `cargo bench`.
If the `gnuplot` command is missing you will see:

```
Gnuplot not found, using plotters backend
```

The benchmarks still execute, but installing `gnuplot` provides nicer graphs.
On Debian/Ubuntu:

```bash
sudo apt-get install gnuplot
```

On macOS (Homebrew):

```bash
brew install gnuplot
```
The `bench_field` suite exercises the BN254 backends and shows the speedup from SIMD dispatch.


The `bench_poseidon` benchmark measures performance of the Poseidon hashing
implementation and automatically selects the SIMD or scalar path.

Additional suggestions for optimising performance can be found in
[docs/performance_tasks.md](docs/performance_tasks.md).

## Merkle Commitments: VM vs Ledger

IVM maintains Merkle commitments during execution to complement ledger‑level commitments. These layers serve different purposes:

- VM root: A Merkle tree over VM execution state (registers and/or memory regions). The VM recomputes this deterministically (and, when enabled, in a parallel but deterministic manner) to produce execution receipts and ZK‑friendly traces. VM roots are ephemeral and scoped to a program’s execution.
- Ledger roots: The node/WSV maintains Merkle commitments for blocks (e.g., transactions in a block) and may expose a world‑state snapshot root for light‑client proofs. These are durable consensus objects and live outside the VM.
- Compatibility: Both use the canonical `iroha_crypto::MerkleTree` type and the same hashing semantics (inner nodes are SHA‑256 of left||right; a missing right child promotes the left). Integration tests ensure roots and proofs match across crates so a proof built in one context verifies against a root computed in the other.
- Determinism: The VM root computation is hardware‑independent. Optional parallel implementations avoid non‑deterministic reductions to preserve identical outputs on all nodes.

In short, VM‑level commitments provide verifiable execution evidence, while ledger‑level commitments provide durable inclusion/state proofs. They are complementary, not competing.

Canonical helpers and re-exports:

- Use `iroha_crypto::MerkleTree<[u8;32]>::from_byte_chunks(bytes, 32)?` (or `from_chunked_bytes_parallel` with the `rayon` feature) to build byte‑chunk trees. These helpers return `Result` and validate chunk sizes (`1..=32`).
- Use `iroha_crypto::MerkleTree::get_proof(idx)` to obtain Merkle proofs; verify with `MerkleProof::<[u8;32]>::verify_sha256`.
- The `ivm` crate re‑exports the canonical type as `ivm::MerkleTree` for convenience; VM adapters like `ivm::ByteMerkleTree` are thin wrappers that build on it.

## Documentation

Generate HTML API docs using Cargo:

```bash
cargo doc --open
```

This builds the crate documentation and opens it in your browser so you can
explore the VM implementation in detail.

You can skip building dependencies with `--no-deps`:

```bash
cargo doc -p ivm --no-deps
```

The rendered API documentation for the latest release is also available online
at <https://docs.rs/ivm>. To include private items in the generated docs set
`RUSTDOCFLAGS`:

```bash
RUSTDOCFLAGS="--document-private-items" cargo doc
```

The `instruction` module in the generated docs enumerates every opcode
constant used by the VM. A convenient summary is also provided in
[docs/opcodes.md](docs/opcodes.md).

## KOTODAMA Source Language

「言霊の幸わうブロックチェーン」

`kotodama` is a higher level language that compiles to IVM bytecode. The
compiler lives in `crates/kotodama_lang` and includes the lexer, parser,
semantic analysis, IR lowering, bytecode emitter, manifest generation, linting,
and source-analysis helpers. It produces the same `.to` bytecode understood by
the VM while surfacing first-release contract metadata for runtime admission and
scheduling.

## Example Programs

IVM programs consist of simple assembly instructions operating on 256
general‑purpose registers. Below are a few toy programs illustrating the style
of assembly understood by the VM. Pseudocode labels are used for clarity.

### Add two numbers

```asm
ADDI x1, x0, 2   ; load immediate 2
ADDI x2, x0, 3   ; load immediate 3
ADD  x3, x1, x2  ; x3 = x1 + x2
HALT             ; stop execution
```

### Conditional asset transfer

```asm
BLTU x13, x12, abort    ; if balance < amount -> abort
SCALL 0x2C              ; TRANSFER_ASSET_SCOPED (r14 = &DataSpaceId)
HALT
abort:
SCALL 0x02             ; ABORT
HALT
```

## Specification Compliance

The interpreter and compiler target one final ABI V1. The [completion record](../../specs/kotodama_ivm_completion.md) distinguishes implemented components from open authenticated State, execution-proof, AXT, memory, hardware, publication and release gates. Component tests do not establish first-release readiness.


## Transaction Concurrency

IVM executes each contract's instruction stream sequentially; it has no in-VM block scheduler.
Transaction-level concurrency belongs to the host. The node pipeline derives deterministic access
sets, runs non-conflicting transactions concurrently, and commits results in canonical block order,
so every node computes the same state regardless of core count.

See `docs/parallel_execution.md` for the host-facing access-set and thread-limit contract.

## Validation Rules

Transactions may be rejected due to invalid signatures, missing authority, and incorrect currency denominations.
