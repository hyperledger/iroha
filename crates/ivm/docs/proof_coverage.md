# IVM semantic and proof-coverage inventory

The inventory lists everything a complete native proof of one IVM invocation must
cover and records what the proof code covers today. It is a coverage guard, not a
proof: nothing in it constrains a witness or authorizes `IvmProved` admission.

- Typed source of truth: [`src/proof_coverage/`](../src/proof_coverage) (`ivm::proof_coverage`).
- Machine-readable artifact: [`proof_coverage_inventory.json`](proof_coverage_inventory.json),
  schema `iroha.ivm.proof_coverage_inventory.v1`, one entry per line.
- Regenerate: `cargo run --locked -p ivm --features dev-tools --bin gen_proof_coverage_inventory -- --write`
  (`--check` verifies without writing).
- Verify: `cargo test -p ivm --lib proof_coverage`.

## Contents

| Section | Entries | Source owner checked by the tests |
| --- | --- | --- |
| `opcodes` | 90 admitted opcodes | `wide::is_valid_opcode` (compile time), `ivm_abi/src/instruction.rs`, the interpreter dispatch in `src/ivm.rs` |
| `reserved_opcodes` | 16 ISO 20022 values | `ivm_abi/src/instruction.rs`; rejected as `InvalidOpcode` |
| `syscalls` | every `abi_syscall_list()` entry | `abi_syscall_list()`, `syscall_name` (`ABI_V1_SYSCALL_METADATA`), the access and metering registries |
| `host_private_syscalls` | Kotodama test helpers | `is_koto_test_syscall`; rejected as `UnknownSyscall` by production hosts |
| `run_phases` | invocation entry, root-call initialization, step preamble and the terminal block | `IVM::run_with_host_ref` in `src/ivm.rs` and `IVM::begin_root_call` in `src/call_runtime.rs` |
| `trap_kinds`, `vm_errors` | every `VmTrapKind` and `VMError` variant | `ivm_abi/src/error.rs`, `IVM::classify_trap`, every constructing source file in `vm_error_producer_scope` |
| `numeric_faults`, `pointer_abi_faults` | every stable fault tag | `from_tag` decoders and `ivm_abi/src/numeric.rs` |
| `components` | unregistered proof components | `iroha_core_privacy/src/execution_proofs/ivm_step_air` and `src/execution_packets` |
| `invocation_obligations` | invocation-wide requirements | reviewed against the components; cited symbols are checked |
| `open_semantics` | unmapped or unresolved semantics | every evidence citation of every record |

Each opcode entry carries its step effect, PC edge, obligation classes, the
`VMError` variants its interpreter arm names directly, the fallible helpers it
propagates and its privacy-tag surface. Each syscall entry carries its relation
class and three separate bindings: `result`, `trap` and `statement`. The `access`,
`metering` and `gas_formula` columns are read from their registries when the
artifact is rendered.

`private_masking` follows one rule: an opcode carries it exactly when one step
reads or writes a privacy tag, that is, when its arm calls a tag accessor or a
privacy helper (`tag_surface`), raises `PrivacyViolation` itself, or dispatches a
syscall. Only `HALT`, `JMP`, `SETVL`, `PARBEGIN` and `PAREND` are outside it.

## Obligation classes

`fetch`, `typed_values`, `initialization`, `memory_ordering`, `pointers`, `calls`,
`copyback`, `faults`, `gas`, `padding`, `vector`, `parallel`, `precompile`,
`continuation`, `proof_composition`, `vm_recursion`, `guest_proof_verification`,
`private_masking`, `host_result`, `state_read`, `state_effect` and
`statement_binding`.

`continuation` and `proof_composition` are proof-system obligations that apply to
the whole invocation. `vm_recursion` is the VM-level one: protected `JAL r1`/`JALS`
calls, the canonical `JALR r0, r1, 0` return and `CALL_CONTRACT*`, bounded by the
1,024 callable-depth limit and, separately, the 32 nested-contract host limit.
`guest_proof_verification` covers `VERIFY_PROOF`, `ZK_VERIFY_BATCH`,
`ZK_VOTE_VERIFY_*` and the AXT-specific `VERIFY_DS_PROOF`; it is not recursive
composition of IVM execution proofs.

## Failure origins

Every `(variant, file)` pair in which non-test code constructs a `VMError` is
recorded and checked against the sources in both directions, across
`crates/ivm/src`, `crates/ivm_abi/src`, `crates/ivm_artifact_admission/src`,
`crates/iroha_core/src` and the SoraCloud host. A match arm, a `matches!` pattern,
a comparison or documentation is not a construction; aliases, `Self::`, imported
variants and the `metered` helper constructors are. `NullifierAlreadyUsed` has no
producer and is tracked as an open semantic. An error that reaches `VMError`
through `?` or `.into()` is attributed to the file holding the conversion.

The origin of each pair is reviewed, not derived. A shared helper lists every
origin through which its construction sites are reachable, never fewer:

- `prepare_rejection`: raised before `run` by artifact decoding, admission,
  entrypoint selection, host setup or argument-record preparation. No trace
  exists; the statement binds the admitted code, manifest and header instead.
- `initialization_trap`: raised inside `run` before the first fetch, by the entry
  check of the shared cycle allowance or by root-call initialization, where the
  argument-decode prepayment is consumed and result- and call-table gas is
  debited. It is a terminal outcome with zero completed steps whose exact error
  and gas the relation must prove; its executed padding cycles are zero.
- `interpreter_trap` and `syscall_trap`: reachable terminal outcomes that the
  relation must prove with exact gas.
- `host_invariant`: a violated VM/host contract; the relation must make it unreachable.
- `local_deferral`: a node-local refusal that is never a consensus outcome and must
  never be provable.
- `outside_invocation`: constructed outside any run by code that reuses the error
  type, such as the executor-upgrade instruction or a local diagnostic check. It
  is never an invocation outcome.

`DecodeDeferred` retains the canonical decoder's original non-wire refusal through
metadata, literal and argument admission, VM errors and Core attempt boundaries.
Its opaque scope is preserved after the caller's decode scope retires. It carries
no allocation-pool release notification and cannot become metered gas or a
deterministic fault. Its presence does not qualify other decoder or verifier
paths that still discard resource causes.

`run_phases` restates the trap tokens and propagated helpers of the four parts
of a run outside the dispatch arms. The terminal block also returns results
without `?` (the recorded contract abort and the shared cycle allowance), so the
tests pin its complete call surface.

## Coverage status

- `uncovered`: no proof code holds a relation.
- `component_only`: an unregistered component holds equations; the invocation
  obligations stay open.
- `complete`: the registered whole-invocation relation discharges every obligation.
  No entry is complete while `COMPLETE_RELATION` is `None`.

Today 58 opcodes are `component_only` and 32 are `uncovered` (`LDLIT`, `JR`,
`HALT`, `SCALL`, `SYSTEM` and every vector, parallel, cryptographic and ZK opcode).
Every syscall is `uncovered`. Only the `OutOfGas` and `AssertionFailed` outcomes
have a component relation, for the final attempted step of the public scalar
segment. `IvmProved` verification rejects unconditionally.

Completion stays open until a relation is registered, every opcode, syscall, trap
kind, fault code and invocation obligation is complete, `open_semantics` is empty
and the default syscall exclusion list is still empty. `completion_blockers`
evaluates each condition on its own, so registering a relation cannot close
coverage while a semantic is open or an entry is incomplete.

## Location

The typed catalog is the successor of the former private
`src/instruction/execution_relation_inventory.rs`, whose opcode table and
compile-time `is_valid_opcode` guard now live in `src/proof_coverage/opcodes.rs`.
There is one catalog and one generated artifact.

## What the proof-code checks establish

The component claims are reviewed from each component's acceptance predicates and
equations. The tests then guard them against drift: every non-test module below
`ivm_step_air` must belong to one component, and the opcode and trap constants a
component's sources name must equal its recorded `referenced_opcodes` and `traps`.
A changed proof file therefore fails until the claims are reviewed. These are
token scans; a referenced constant is not a coverage claim and the scans are not
behavioural proof-coverage verification. `crates/ivm` cannot depend on the proof
crate, so the proof crate's own tests remain the evidence that a component accepts
what it claims.

## Changing the inventory

Add or change the typed entry, regenerate the artifact and run the tests. Never add
a syscall exclusion, delete an open-semantic record to close the inventory, or mark
an entry covered without a relation exercised by a test.
