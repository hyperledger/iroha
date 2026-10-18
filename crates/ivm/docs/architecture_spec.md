# Iroha Virtual Machine Architecture

IVM is the deterministic 64-bit virtual machine used by Iroha 3 smart contracts. Kotodama compiles
to IVM bytecode (.to); RISC-V-like field layouts are implementation details and do not define a
separate target architecture.

This document describes the first-release implementation. ABI version 1 is the only accepted ABI.

## Program format

- Every executable instruction is one naturally aligned 32-bit little-endian word.
- Program loading validates metadata, instruction boundaries, opcodes, indexed literals, syscall
  policy, and the terminating HALT before execution.
- Compact 16-bit and mixed-width instruction streams are rejected.
- The only mode bits are ZK and VECTOR. Unknown bits are invalid metadata.
- Prepared programs cache validated decode results. The execution loop consumes the canonical
  prepared representation directly; there is no compatibility decoder or alternate interpreter.

## Registers and memory

IVM has 256 64-bit registers. r0 is hardwired to zero. In ZK mode each register also carries a
privacy tag, and instructions either propagate compatible tags or trap before a private value can
affect a public control-flow or host boundary.

Memory is byte-addressable and divided into code, heap, input, output, and stack regions with
explicit permissions. Multi-byte guest accesses must be naturally aligned and fully in bounds.
Private guest spills are stack-only. Their byte ranges are tracked so partial public overwrites
cannot silently declassify a value; reset, program replacement, and leaving ZK mode scrub private
bytes.

The register Merkle tree is rebuilt lazily after writes, resets and runtime-template restores. A
burst of register or tag updates marks the tree dirty without hashing on every write; the first
root or path request rebuilds one canonical tree, and subsequent reads reuse it until the next
mutation.

## Preparation and runtime retention

`ivm_cache_max_bytes` supplies one aggregate retention budget (64 MiB by default);
zero disables retention. Immutable artifact images, decoded/prepared operations,
metadata, literal indexes and analyses carry a reservation in their allocation
owner. Dropping a cache entry does not refund another VM's live borrower. Native
collection capacities and conservative B-tree node bounds account for cache
indexes; index storage is physically freed when retention is denied.

Contract and user-provided executor runtime leases restore their baseline on
return, error and unwind. Pooled memory
images, register/memory Merkle arrays and call-frame storage carry independent
owners. Checkout moves uniquely owned runtime storage into active accounting;
shared immutable owners keep their retention charge. Admission never waits for
an executing borrower, and a denied cache admission executes cold with identical
validation, gas and results. Reducing the budget clears idle Core/global cache
references while outstanding borrowers remain charged until destruction.

Each memory image owns two fixed bitmaps with one bit per 32-byte Merkle leaf:
pending commit changes and changes since the runtime baseline. Constructor and
snapshot plans reserve the complete bitmap geometry from the original execution
lease; local images use the aggregate cache accounting owner. Stores and warm
reset change initialized words without growing tracking sets. Bitmap backing
keeps its charge through retention and final borrower release. Memory commits
stream the original set bits into fixed leaves and update cached paths in
ascending order without copied index or digest vectors. Existing full-rebuild
and hardware selection still apply for large updates.

`cache_memory::memory_stats()` exposes retained/active bytes, their measured
resident total, the peak measured reservation, and the number of active owners
with an unmeasured dynamic footprint. Metadata which cannot be
normalized into a measured Norito owner remains valid and uncacheable. Embedded
trigger descriptors currently remain uncacheable because independently cloned
JSON backing can outlive their aggregate metadata owner.
Cache-control blocks, shard arrays and eviction-registry capacity remain active
infrastructure when retention is disabled. TODO: Complete active scratch
ownership/admission and borrowed/evicted observability before treating these
counters as a complete process-memory bound. Independently shared trigger metadata
still needs its own allocation reservation.

Fallible physical call-frame allocation returns a typed local execution deferral,
separate from deterministic guest bounds faults. Core preserves the reason across
nested calls, executor validation and query validation; the outer output owner
abandons the attempt before retaining gas, fees, rejection rows or trigger
completion. Original capacity-refusal observations propagate through Core to the
Sumeragi retry owner without creating a durable ledger rejection. A reason-only
refusal requires local recovery. TODO: complete production root/nested allocation
funding, configuration-reload pool custody and notification-safe cache release.

## Execution and gas

The contract interpreter is a single sequential fetch-decode-execute loop. This keeps trap
precedence, gas exhaustion, privacy checks, and proof traces in exact program order.

Each opcode has one ABI-v1 gas rule. Vector costs scale with the declared logical vector length,
not the host SIMD width. Cryptographic and staged syscall work is charged before bounded parsing or
expensive host work. Hardware selection and block scheduling are never consensus-metered.

max_cycles bounds execution and determines ZK trace padding when enabled. Branches always charge
their fixed instruction and cycle costs; execution history and predictor state cannot affect the
result.

## Zero-knowledge mode

ZK mode enables privacy tags, private-memory range tracking and deterministic
trace padding. Secret-dependent public branches, addresses, traps and host
arguments are rejected. Register/memory Merkle logs and diagnostic traces do not
constitute a complete execution proof. `IvmProved` admission is closed; private
invocation requires the complete native STARK relation and State-owned finalized
full-state commitments. Those
release gates remain open in the [completion record](../../../specs/kotodama_ivm_completion.md).

## Vector and cryptographic acceleration

The VECTOR mode enables logical vector opcodes. The logical lane count is part of program
metadata and is capped by ABI policy. Scalar, SIMD, Metal, and CUDA helpers must return byte-for-byte
identical outputs. Runtime feature detection selects only a throughput implementation; a
deterministic scalar fallback remains authoritative.

Optional acceleration can fail closed or fall back without changing opcodes, gas, traps, register
values, memory, or proofs. Qualification tests compare available accelerated paths with the scalar
implementation.

## Transaction concurrency

Each contract executes sequentially and IVM has no block scheduler. Hosts own transaction-level
concurrency: they pass declared access sets through `IVMHost::begin_tx`, receive observed accesses
from `IVMHost::finish_tx`, and commit results in canonical block order. There is no hardware
transactional-memory path.

Thread count, completion order, and CPU capabilities affect throughput only. See
[parallel_execution.md](parallel_execution.md).

## Host boundary and ABI

All compiled functions use caller-owned argument/result tables: `r10/r11` carry
argument address/count, `r12/r13` result address/capacity, and returns carry result
address/exact initialized count in `r10/r11`. Each table is aligned and bounded
to 8,192 words (64 KiB). Mandatory callable descriptors bind table roles and
frame bounds; the runtime enforces initialization, ownership and storage lifetime.
See [calling convention](calling_convention.md) for the canonical table layout.

SCALL delegates to IVMHost under the ABI-v1 syscall policy. Unknown or disallowed syscall
numbers trap as VMError::UnknownSyscall. Pointer-ABI objects are validated for type, version,
length, checksum, ownership, and privacy before use.

Contract admission checks the code and ABI hashes embedded in manifests. Since this is the first
release, obsolete encodings and speculative compatibility surfaces are removed instead of retained
as alternate execution paths.

## Safety invariants

- No consensus-visible behavior depends on wall-clock time, thread scheduling, prior VM history,
  or optional hardware.
- Failed transactions expose no partial state batch.
- Invalid addresses, alignments, metadata, opcodes, syscalls, and pointer objects trap explicitly.
- Private data cannot cross a public boundary without an allowed commitment or reveal operation.
- Runtime state mutation uses safe Rust; acceleration-specific unsafe code is isolated behind
  parity-tested helpers and deterministic fallbacks.

### Write-log allocation custody

Memory records writes through private row and payload owners. Row growth and payload
copying are reserved before guest bytes or output cursors change. Each payload is
scrubbed on final drop, and clearing the log retains the charged row capacity.
`Memory::try_write_log_snapshot` returns an independently owned immutable snapshot;
it holds no lock across later stores. The raw `Vec<WriteLogEntry>` snapshot and
mutable public byte-vector escape are removed. Entries expose `address()` and
`bytes()`; snapshots are explicitly fallible to clone.

State-owned logs reserve each append's complete replacement-row and payload
layouts from their original finite execution pool before physical allocation or
guest mutation. A replacement keeps the old row backing charged until after all
entries move into the completed new backing; unchanged payload owners move with
their entries. The old allocation is destroyed before its original charge is
refunded. Capacity and physical allocation failures leave guest bytes and the
existing write history unchanged and use the existing local execution-deferral
path. Cache admission cannot supply execution credit.

Detached snapshots are explicit independent copies: they reserve the complete
exact row and payload demand from that same original pool. Their fallible clones
retain this rule after the source VM disappears. Runtime-template copies instead
partition the existing parent reservation after checking exact pool identity;
their actual row/payload owners hold those split charges without retaining a
duplicate aggregate charge for the same bytes. Each allocation also retains the
existing aggregate retention-accounting owner. A shared outer borrower keeps all
charges until final backing destruction; shrinking either budget does not refund
live storage. Standalone local Memory uses its existing retention owners and
never becomes a fallback for a refused State-owned allocation.

Full worker snapshot admission, hardware scratch and complete nested-execution
admission remain open execution-memory gates. The read/write-log subsets of
worker copies are funded from the original pool even when the worker's other
private copies still use local accounting. No gas formula changes;
Core preserves resource deferrals as operational outcomes before rejected-work
fee accounting. The direct VM can contain attempted work when an opcode defers,
so callers must follow the existing attempt rollback/retry boundary rather than
resume it as though the failed attempt were a successful instruction.

### Read-log allocation custody

Reads use a specific row owner. State-owned Memory reserves the complete next
row array from its original finite execution pool before allocation, diagnostic
publication or caller output. The old array stays charged while its initialized
ranges are copied to the replacement. Diagnostic refusal discards that replacement
and leaves the old rows, capacity and output unchanged. Successful publication
installs the complete next history before destroying the old backing. Appends
within existing capacity and clear/reset retain the same prepaid array.

`Memory::try_read_log_snapshot` replaces the raw-vector read snapshot directly.
Its immutable result owns an independent exact copy and exposes only a borrowed
range slice. Snapshot creation and explicit fallible cloning reserve from the
same original pool; template copying partitions the original prepaid parent
lease after an identity check. Each backing keeps both execution and retention
charges until actual deallocation. Shared outer borrowers add no duplicate row
charge, and budget shrink or eviction cannot refund live backing.

Memory defers allocation-release callbacks until the read-log mutex has released,
including diagnostic refusal and unwind. Invalid address/alignment errors still
precede row admission. Ordinary guest loads, unprepared instruction fetches and
trusted call-result reads retain their existing tracking rules; quote-only
inspection and prepared diagnostic fetches remain separate. Allocation refusal
uses the existing operational deferral and attempt rollback boundary, without
changing gas schedules or transaction validity. TLV/numeric decoders and signature
preflight/verification retain the complete operational error instead of reporting
malformed input or a false verification decision. INPUT cursor reconstruction
performs its tracked scan fallibly and publishes the valid-prefix cursor only
after the scan completes; admission failure cannot silently truncate that prefix.
Kotodama test invocation propagates operational failures before rejection matching,
and the outer test runner reports an execution failure rather than a contract
rejection. Deterministic semantic decoder errors retain their existing mappings.

Private-memory write cleanup still requires a separate admission/error-propagation
cut: byte-wise scrub can exhaust write-row credit, and its existing boolean result
is erased by reset or mapped to PrivacyViolation by mode/load transitions. This
read-owner change does not close that gate or the remaining active-memory owners.

## Fixed canonical memory Merkle nodes

Memory construction and runtime-template copying prepay the complete canonical
SHA-256 node geometry alongside the memory image, leaf digests and dirty bitmaps.
The checked Crypto geometry includes its exact retained node capacity; the actual
allocation must match that request before the owner is published. Funded nodes
carry a split charge from the original execution lease. Local nodes use the same
aggregate retention accounting as other IVM backing. Both charges remain until
the canonical tree's node array has been destroyed. A freshly zeroed image has
identical leaves, so construction computes one pair hash per tree level and
fills each level with the bit-identical canonical nodes.

Every byte tree retains this node storage. Sparse updates use canonical leaf-to-root
updates; dense CPU or successful hardware leaf replacement marks the existing
nodes stale. Root and proof queries rewrite their retained breadth-first slots
using Crypto's existing SHA-256 relation. Warm resets keep node storage even when
the known template root lets execution defer rewriting it. No query allocates a
replacement canonical node array or queue. Proof output vectors, hardware block
and digest scratch, telemetry/Rayon bookkeeping and worker snapshot resources are
separate from this canonical-node backing guarantee.

`ivm_merkle_rebuild_total` counts completed in-place canonical node refreshes once
at the refresh owner. It excludes initial construction and independent template
copies. Dense leaf recomputation is classified by the memory-commit path metrics
and does not separately increment this counter. Incremental path updates retain
their separate leaf-update counter. Byte trees have no infallible `Clone` wrapper;
internal copies explicitly choose the fallible local or original-lease path.
