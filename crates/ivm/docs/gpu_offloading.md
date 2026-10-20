# IVM hardware acceleration

IVM computes the same public result, gas, errors, state effects, event order,
and verification decision on every hardware class. SIMD is compiled into all
builds and selected by CPU capability. Ordinary macOS builds now compile the
Metal backend by default; the Metal feature has target-scoped dependencies and
is inert on other operating systems. The node's file-loaded `[accel]` policy
enables the available backends by default and provides operator opt-outs and
GPU limits. Developer environment shims are ignored by shipping binaries.

Metal and CUDA may be used only after their own device and kernel admission
checks pass. A backend failure quarantines the affected candidate, discards its
unpublished output, and lets the caller recompute from the original input on a
qualified fallback. Selection and fallback do not change consensus semantics.
Byte-root selection uses one exact public `(byte length, chunk width, leaf count)`
profile per qualified Metal owner. It measures both all-zero and public nonzero
samples against the actual canonical SHA2 CPU constructor; IVM SIMD policy does
not identify that separate CPU implementation. The complete ordinary Metal root
operation includes padded blocks, both kernel stages, transfers, readback and
cleanup. The fastest measured CPU sample and slowest Metal sample must show a
clear Metal win. Every sample must match the canonical root. Input contents never
select a profile, and no interpolation authorizes another chunk or tail geometry.
Synthetic bytes, the canonical fixed node backing and native host buffers retain
original process resource credit until their physical owners drop. Tree
construction has its own exact chunk/tail profile against the actual IVM
parallel leaf builder and canonical node construction. Its returned CPU and GPU
sample trees remain alive beyond the construction timers; both backings are
admitted from the original process host pool before either is constructed.
The CPU key identifies qualified native SHA or scalar execution and the immutable
global Rayon pool's worker count. Calls already inside a Rayon pool decline this
profile until that pool has its own explicit cost owner. Captured caller scalar
restrictions and synthetic receipt routing follow every worker, while current
file policy can still decline native work. Production and synthetic SHA work pay
the same atomic accounting in distinct counters. A mixed CPU sample cannot
qualify a profile, and zero-leaf shortcuts cannot establish native execution.
Retained-tree rehashing measures its exact fixed leaf count, chunk width and
consumed public byte extent against the same ordinary parallel CPU update plus
canonical root refresh. Missing fixed leaves are zero-filled; bytes beyond the
retained capacity do not affect the operation. Both synthetic retained trees are
funded before construction and survive all update timers. Native readback retains
its original physical owner and destination; after taking both destination locks,
it rechecks policy, quarantine and the CPU baseline before copying any leaves,
then completes canonical refresh under that owner. Refusal leaves both original
representations unchanged. Configured operator floors remain effective. BN254 and
Poseidon batches use the bounded CUDA cost path described below. Other helpers
still use fixed workload thresholds;
complete signed cost profiles remain open release work.
An individual Keccak permutation or AES round runs on the CPU because its
transfer and launch cost exceeds the work. AES round batches use one GPU batch
dispatch only after the public transfer-size floor; small Ed25519 batches also
stay on the CPU. The direct single-operation GPU entrypoints remain in the
hardware qualification gate. Native CPU AES preserves the scalar V1 raw-key
round semantics on ARM and x86.

## Native CPU AES

One process-lived owner per encryption/decryption direction qualifies fixed public
round states and keys against the scalar implementation. Capability detection,
file-loaded `enable_simd`, and forced-scalar policy precede every native entry.
Busy admission uses scalar immediately; parity failure or unwind leaves that
direction quarantined. Policy changes preserve successful admission. Native output
remains staged until the original owner and policy accept it, then the matching
direction receives completion credit. Public probes receive no completion credit.

Metal AES calibration measures the exact public family, round count and block
count using two fixed public patterns and three trials per pattern. It uses the
same allocation-free, block-major CPU traversal as ordinary fallback, with
destination preparation outside both operation timers. Profiles bind the actual
scalar/native CPU owner. Every sampled round must use
that baseline; a policy or admission change discards the comparison and permits
later retry without quarantining a healthy GPU. Synthetic rounds perform the same
counter update into a separate owner-resident counter, keeping production receipts
honest without omitting accounting cost from the CPU measurement. Metal samples
also use the production in-place adapter and its same owner lookup and saturating
receipt updates, directed into separate synthetic counters.
Each sample retains four exact host backings (keys, original blocks and two
destinations) from the original process resource owner. Admission precedes each
allocation, and all four remain charged through both patterns, measurement,
refusal and unwind. Sample host backing is bounded by 99,328 bytes. The six
CPU trials and six native dispatches each perform at most 786,432 block-rounds;
native buffers retain their separate original resource charges. One CPU baseline is
captured before scanning device profiles and retained with the selected family,
round count, block count and physical owner. Output acceptance rechecks that same
baseline inside the original device/configuration guard immediately before copy.
A changed CPU baseline leaves the destination unchanged and declines the attempt
without quarantining the healthy GPU.

```sh
cargo test --locked -p ivm --lib aes::cpu::tests::required_arm_aes_executes_production_paths_and_preserves_policy -- --exact --ignored --nocapture
cargo test --locked -p ivm --lib aes::cpu::tests::required_x86_aesni_executes_production_paths_and_preserves_policy -- --exact --ignored --nocapture
```

These explicit physical gates require native capabilities, exact per-direction
completion counts, arbitrary round parity, the independent FIPS-197 cipher vector,
forced-scalar behavior, and file-policy opt-out. Scalar fallback cannot satisfy
them. Default state-machine tests cover contention, quarantine, staged-output
rejection, policy changes, calibration accounting, and unwind. Component evidence
remains separate from an unchanged release candidate and full-path calibration.

## Native CPU SHA-256

Ordinary builds include AArch64 SHA2 and x86-64 SHA-NI compression routines.
Runtime CPU detection, the file-loaded `enable_simd` policy, and an explicit
forced-scalar choice all precede native entry. One process-owned admission record
compares fixed public blocks and chaining states with the scalar implementation.
Admission contention immediately uses the scalar path; a mismatch or unwinding
attempt leaves the owner quarantined. Every operation preserves the caller's
original state until the staged native result is accepted. Only accepted
production operations receive completion credit, excluding admission probes.

Run the required gate on each corresponding physical runner:

```sh
cargo test --locked -p ivm --lib vector::sha256_cpu::tests::required_arm_sha2_executes_production_path_and_matches_scalar -- --exact --ignored --nocapture
cargo test --locked -p ivm --lib vector::sha256_cpu::tests::required_x86_sha_ni_executes_production_path_and_matches_scalar -- --exact --ignored --nocapture
```

Each architecture-specific test runs in an isolated process, requires its CPU
capabilities and exact production completion counts, checks arbitrary chaining
states and padded messages against scalar and independent digest references, and
checks both operator opt-out and forced-scalar behavior. Scalar fallback cannot
satisfy the gate. Default owner tests cover refusal, sticky quarantine, discarded
staged output, unwind, and counter accounting without requiring native hardware.
These component checks do not establish fastest-path selection, unchanged-candidate
gas calibration, or mixed-hardware validator qualification.

## Metal on macOS

The process retains one charged record for each observed Metal registry identity,
including quarantined devices. Discovery enumerates devices independently within
`resource_limits.discovery_ordinals` and `resource_limits.devices`. The separate
`max_gpus` cap counts healthy initialized or initializing owners; a failed first
GPU does not consume the only active slot. A complete bounded enumeration also
quarantines previously observed identities that have disappeared; a truncated
inventory cannot establish absence. Reappearing identities retain their original
quarantine. `Some(0)` prevents discovery and native
entry. Concurrent borrowers retain their original pipeline, health and allocation
owners. Operator opt-outs and discovery restarts never clear physical quarantine
or forgive uncertain command/buffer charges.

A private device lease pins public synthetic calibration and the operation it
selects, including both stages of a Merkle root. Completed Merkle host readbacks
retain that original lease and recheck its eligibility, file policy and physical
quarantine before returning results; refusal preserves the inputs for fallback.
Merkle calibration executes the ordinary leaf and pair adapters, including the
same completion-accounting work directed into separate synthetic counters.
Driver completion receipts do not themselves authorize publication after a later
policy change or quarantine. Merkle, AES batch and Ed25519
batch selection compares qualified costs across eligible devices and retains the
CPU comparison and configured workload floors. Byte-root and BuildTree profiles accept exactly
the measured geometry within 8,192–65,536 leaves and chunk widths 1–32; differing
public geometry requires a new bounded sample after the original owner's cooldown.
Rehash profiles also require exact measured geometry, within 8,192 leaves and the
canonical maximum Memory image (229,376 leaves). This includes every actual V1
Memory shape, from 100,352 to 229,376 leaves. A Rehash profile cannot authorize
root-only or tree-construction work. AES selection accepts only the exact measured
family, round count, block count and CPU baseline within 32–2,048 blocks and
1–64 rounds. Each physical device retains four inline family slots, each holding
one exact comparison. Across both public patterns the comparison uses the fastest
CPU trial and slowest Metal trial, rejects more than fourfold variation within
either pattern, and requires a Metal win greater than ten percent. Quarantine
precedes cache lookup. An admitted attempt starts a thirty-second cooldown before
sampling; a CPU change or unwind preserves it, while scheduler refusal starts no
new cooldown. A matching cached comparison remains usable during cooldown.
Unsupported geometry declines Metal before discovery or calibration. Ed25519 uses
an exact ordered message-length profile instead of count interpolation: 16–512
items, at most 64 KiB per message and 512 KiB total. An unsupported geometry
declines Metal without changing validity or caller storage. These bounded estimates
do not establish fastest-path qualification outside their admitted geometry. New calibration shares one sampling
deadline across devices. Discovery and each public calibration family retain a
nonblocking fair cursor across passes, advancing before an actual attempt. A slow
transient failure cannot repeatedly take the first turn. Candidates deferred by
an exhausted budget or a busy calibration owner receive no new retry penalty;
cached profiles remain comparable when the sampling deadline expires. If a native
callback unwinds, subsequent discovery/calibration recovers only its scalar
scheduler timestamp and cursor, preserving the recorded cooldown and next turn.
Contention still declines immediately. Physical quarantine and coupled registry
or cost-profile mutexes are not reset by scheduler recovery. An explicit discovery
restart retains its existing meaning of clearing only the retry timestamp. Discovery and calibration check time budgets between native operations;
a single command retains its existing ten-second completion bound.

Rust registry storage is reserved from the shared process metadata envelope before
allocation. Admission, losing construction and refunds occur outside registry
writers. The initial physical record capacity is retained for the process
lifetime; increasing that storage ceiling requires a process restart. Native
buffer backing and command permits retain their original shared resource charges.
A command failure quarantines only its original physical device. Uncertain work
retains native storage and permits; another healthy device can continue within
remaining shared capacity. Destination copies happen only after exact-owner
acceptance, so declined work recomputes from its original input. AES attempt output
retains and rebinds its selected device through the final copy, including direct
API calls entered without an existing thread-local physical binding.

The exported `verify_ed25519_batch_items_into` helper borrows exact public lengths
for lookup and generates independent public messages of those lengths for
calibration. Its one fixed profile slot is prepaid with the original physical
state; all synthetic message storage, borrowed views and result arrays reserve
from the original process resources before construction. Three trials compare the
same strict CPU traversal and real Metal Items adapter, including challenge
hashing, native buffers, transfer, completion, validation and cleanup. Selection
uses the slowest GPU trial against the fastest CPU trial with a 10% margin.
A different geometry has a 30-second retry cooldown, an eight-second shared
sampling budget, and no extrapolation. The compiled dalek/SHA-512 baseline is
process-lived; it is independent of the IVM vector forced-scalar override.
TODO: integrate the separate ordered `verify_ed25519_batch` opcode request path;
this Items helper correction does not accelerate that sequential CPU entrypoint.

Synthetic Ed25519 and AES dispatches execute the same physical-owner lookup and
atomic receipt work as production, into separate prepaid counters. Scoped receipt
selection restores through nesting and unwind. Driver completion receipts remain
distinct from full-result parity and publication checks.

```sh
cargo test --locked -p ivm --features metal-hardware-tests --lib vector::metal_ed25519_cost::qualification::required_metal_ed25519_exact_geometry_measures_real_items_without_production_credit -- --exact --nocapture
```

This required physical control
covers empty, 32-byte and mixed messages through 64 KiB, original-owner synthetic
counts, real production Items calls, and the exported automatic helper using the
genuinely measured profile. A measured CPU winner stays on CPU; a measured GPU
winner must produce its exact physical receipt. This is component evidence.

The 16 production pipeline families cover vector arithmetic and bit operations,
SHA-256 compression and Merkle helpers, Keccak, AES round/batch helpers, and
Ed25519 verification. Startup probes and diagnostic commands produce no production
execution receipt.
Run the required hardware gate on a Metal host:

```sh
cargo test --locked -p ivm --features metal-hardware-tests --lib required_metal_hardware -- --test-threads=1 --nocapture
```

The gate runs in an isolated process and requires the complete allowed native
identity inventory to have charged records. It fails when Metal is absent, an
observed device cannot qualify, a pipeline falls back to CPU, or parity breaks.
For every recorded device it compares all 16 families against CPU references at
several sizes, including odd Merkle reductions and valid and invalid signatures.
`metal_completed_dispatches(MetalKernel)` exposes aggregate production counts;
the gate also requires positive counts bound to each exact physical identity. Completion alone does not
establish correctness, so the scalar comparisons are mandatory. Local M1 Ultra
evidence is recorded in `target/kotodama-metal-local-evidence.json`; that
changing-worktree component run is not an unchanged release-candidate result.

An additional unbound direct AES control requires true accepted output and exact
physical counters for all four batch families, for both destination and in-place
APIs. This prevents an outer qualification binding from concealing an escaped
output owner's acceptance failure:

```sh
cargo test --locked -p ivm --features metal-hardware-tests --lib vector::metal_qualification::required_metal_unbound_aes_keeps_exact_owner_through_copy -- --exact --nocapture
```

The separate two-device destructive control requires actual hardware and cannot
pass on a one-device runner:

```sh
cargo test --locked -p ivm --features metal-hardware-tests --lib vector::metal_qualification::required_metal_two_devices_isolate_quarantine -- --exact --nocapture
```

It checks uncertain backing/permit retention, zero-cap refusal, sticky quarantine
across policy reload, and actual second-device dispatch with `max_gpus = 1`.

Metal release qualification still needs signed artifact provenance, authenticated
benchmark profiles, coverage for other kernels, device/driver/artifact matrix
evidence, and mixed-hardware validator parity. Metal physical failures currently
quarantine the affected device; finer independent kernel quarantine remains open. The process owner loads an embedded precompiled V1 Metal
library and performs no startup shader compilation. The local optional Xcode
Metal toolchain built the pinned candidate; release signing and unchanged-
candidate device qualification remain open.

## CUDA artifacts and runtime

The patched `cust_raw` boundary loads the CUDA driver at runtime. A CPU-only
machine can start a CUDA-enabled binary without a driver. Linux loads
`libcuda.so.1` (including the WSL system path); Windows restricts
`nvcuda.dll` to System32. Missing drivers or symbols leave the CPU path
available. Linux/Windows daemon dependencies now select the existing CUDA
feature automatically; macOS retains Metal. The one private source-owned
`REVIEWED_CUDA_BUNDLE_PINS` is currently `None`. Genuine absence permits
CPU-capable ordinary builds in every profile; supplied unreviewed, partial or
malformed material is an integrity error. Cargo and startup invoke no CUDA tool
and obtain no approval from environment values.

One immutable optional owner retains the exact ten-family authenticated bytes.
The build and runtime adapters share the sole canonical signed V1 relation.
Runtime absence refuses before CUDA discovery/private staging and grants no
native completion or calibrated-profile credit. Shipping and required-hardware
gates refuse without genuine source approval and actual completions. Explicit
two-run candidate generation uses only the existing offline producer.

The ten source families are AES, bitonic sort, BN254, Poseidon, SHA-256,
SHA-256 leaves, SHA-256 pair reduction, SHA-3, signature, and vector. The
retired floating-point diagnostic kernel is outside this inventory. Startup
never downloads or compiles kernels. See [the CUDA artifact record](../cuda/README.md)
for the open pinned-toolchain, two-run reproducibility, signed provenance, and
real-hardware gates.

The common process acceleration envelope owns CUDA discovery, primary contexts,
modules, streams, host staging, pinned buffers and device buffers. File-loaded
`[accel.resource_limits]` supplies finite enabled defaults; explicit zero forbids
that resource. Admission never waits for capacity. A refused attempt leaves the
original input available for a complete CPU recomputation. State destinations
retain their original execution lease; native SDK snapshots and outputs use
charged process-host owners until the final foreign-runtime copy.

Discovery treats devices independently and checks public launch geometry against
capabilities. Kernel failures exclude the device/kernel/artifact candidate;
uncertain context, stream or completion state quarantines the physical device.
A timed-out attempt retains unsafe-to-free storage and its charges. Late driver
completion cannot undo that quarantine. Task scopes retain their selected device
through compound operations. There is no second GPU manager or parallel
admission registry. Native batch helpers fill caller destinations only after
complete result validation; ordinary helpers handle qualified CPU fallback.

BN254 Poseidon V1 parameters have one canonical fixed-byte owner in
`iroha_zkp_poseidon::poseidon::bn254_v1`: 648 full fields, widths/rates 3/2
and 6/5, x^5, 8 full rounds with 57/60 partial rounds, and the exact complete
circomlibjs v0.1.7 constants/MDS. The Iroha H.2 fixed-arity mode puts
`arity * 2^64` in capacity coordinate zero, adds inputs into rate coordinates,
and returns coordinate one. Six inputs require two additive rate-five blocks.
The 64-bit opcode outputs are not commitments. The separate FASTPQ variable
word sponge retains its padding and coordinate convention using the new table.

Strict canonical initialization, explicit width/round-count exports, IVM
four-limb banks and FASTPQ flattened banks use fixed inline arrays. Independent
full-field vectors and fresh-process allocation controls cover parameter and
mode behavior; they do not establish a constrained BN254 Halo2 relation. CUDA
uses the same fixed mode in one authenticated invocation and publishes only
after validating the complete output state. GPU request buffers, cancellation,
signed artifacts and physical qualification remain separate requirements.
The previous tables and untagged modes are removed; ABI V1 opcode outputs and
shared fixture hashes change together without a compatibility path.

Ordinary BN254 addition, subtraction and multiplication, and Poseidon2/6 batches,
retain five separate inline cost profiles in each original device policy owner.
Profiles bind the exact independently admitted PTX and actual CPU field backend.
Public synthetic operands are measured at 64, 256, 1,024 and 4,096 elements, with
three trials per size. GPU timings include transfers, launch, waits, complete
result validation, copyback and staging cleanup; BN254 includes its extra input
scan and Poseidon includes parameter packing/uploads. BN254 results must match
the independent field relation, and both Poseidon results must match fixed public
known answers checked by the separate circuit reference suite. Conservative
CPU/GPU trial bounds require a ten-percent estimated win; bounded interpolation
ranks currently qualified candidates only within the sampled span. This is
bounded calibrated selection, not a global optimality or release qualification
claim. Outside the sampled span, ordinary batches use CPU. There is no
last-sample extrapolation.

One nonblocking scheduler admits at most one new candidate per ordinary call,
rotates the first device between calls and shares an eight-second pass deadline
checked between complete attempts. This deadline does not forcibly cancel a
synchronous CPU computation or native kernel already in progress. Scratch arrays
reserve original process-host
credit before allocation. Local pressure, policy changes and unstable timing
defer selection with a cooldown, preserving successful kernel admission. Native
faults retain existing quarantine, and a completed parity mismatch quarantines
the exact kernel. Calibration receives no production completion credit. The
selected token retains the original device/kernel/artifact through copyback and
rechecks policy, CPU identity and admission; refusal recomputes the complete batch
from the original inputs. CPU field dispatch applies the current SIMD policy on
each lookup, including after configuration reload. Explicit CUDA batch APIs still
serve hardware qualification independently of cost selection.

`cuda_completion_snapshot(slot)` reads the original device UUID/driver owner and
its separate `CudaKernel` completion counts. An unobserved slot has no historical
credit; a busy registry is reported separately and cannot stand in for a zero
baseline. Counters saturate, survive policy opt-out and quarantine, and exclude
admission probes, malformed output, backend failures and CPU fallback. The
required hardware control checks the exact kernel's increase on the pinned
original device. These local observations do not establish result parity or
performance without the separate comparisons and candidate qualification.

IVM Metal no-copy buffers, command permits and Rust registry records use this
common resource envelope. These controls do not establish FASTPQ Metal physical
custody or remove its separate runtime-compilation path. CUDA cost ranking beyond
these BN254/Poseidon samples, authenticated performance profiles, complete fastest-path
coverage, opaque native
pipeline accounting and physical resource qualification remain open.

Shared profile/state and fixed Poseidon CPU tests run without a GPU and do not
qualify native selection. Unit tests, admission probes and locally measured
profiles neither supply the missing thirteen signed bundle artifacts nor qualify
physical GPU performance.
The missing genuine signed PTX bundle still prevents the CUDA-enabled consumer
build, so the native calibration adapter and selected path require that build and
physical device evidence before release.

Run the mandatory CUDA hardware gate on each qualified CUDA runner:

```sh
cargo test --locked -p ivm --test cuda_hardware --features cuda-hardware-tests -- --nocapture
```

It requires real completed kernel work on every discovered usable device and
scalar parity for all ten families. Driverless policy tests establish loading
and state transitions only; they do not qualify GPU execution. The same
candidate must then pass CPU/SIMD/Metal/CUDA parity and a four-validator
mixed-hardware network with mandatory signed RS16 payload availability before
release.
